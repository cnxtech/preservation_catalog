### schema explanation



### how to use transactions appropriately

The Rails API docs: http://api.rubyonrails.org/classes/ActiveRecord/Transactions/ClassMethods.html

General advice:
* Please use `ApplicationRecord.transaction` for clarity and consistency.
  * Functionally, it doesn't matter whether `.transaction` is called on a specific ActiveRecord class or object instance, because the transaction applies to the database connection, and all updates in a given thread of operation will be going over the same database connection (it is possible to configure ActiveRecord to do otherwise, but like most applications, we don't).  To reduce confusion, it seems best to just always invoke it via the super-class, so that it's clear that the transaction applies to all object types being grouped under it.
* If two or more things should fail or succeed together atomically, they should be wrapped in a transaction.  E.g. if you're creating a PreservedObject so that there's a master record for the PreservedCopy that you'd like to create, those two things should probably be grouped as a transaction so that if the creation of the PreservedCopy fails, the creation of the PreservedObject gets rolled back, and we don't have a stray lying around.
* Don't wrap more things than needed in a transaction.  If multiple operations can succeed or fail independently, it's both semantically incorrect and needlessly inefficient to group them in a transaction.
  * Likewise, try not to do too much extra processing in the `Application.transaction` block.  It's fine to wrap nested chains of method calls in a transaction, as it might be a pain to decompose your code such that the transaction block literally only contained ActiveRecord operations.  At the same time, the longer a transaction is open, the higher the chances that two different updates will try to update the same thing, possibly causing one of the updates to fail.  So, if it's easy to keep something unnecessary out of the transaction block, it'd be wise to do so.
* In the unlikely event that you're tempted to pro-actively do row-locking, e.g. due to concern about multiple processes updating a shared resource (e.g. if multiple processes were crawling the same storage root and doing moab validation), the Postgres docs seems to advise against that.  Instead, specifying transaction isolation level seems to be recommended as the more robust and performant approach.
  * Isolation level can be passed as a param to the transaction block, e.g. `ApplicationRecord.transaction(isolation: :serializable) { ... }`
  * `serializable` is the strictest isolation level: https://www.postgresql.org/docs/current/static/transaction-iso.html
    * relevant Rails API doc: http://api.rubyonrails.org/classes/ActiveRecord/ConnectionAdapters/DatabaseStatements.html#method-i-transaction
    * more background and advice from the PG wiki: https://wiki.postgresql.org/wiki/Serializable
  * If there is actually little contention in practice, the PG docs seem to indicate that specifying isolation level, even something as strict as `serializable`, should have little to no overhead (though it could increase chances of failed updates if there is actual resource contention, though code should already be prepared to handle failed DB updates gracefully).  As such, there seems to be little risk to erring on the side of a strong isolation level when in doubt.
  * *probably shouldn't* do it this way: http://api.rubyonrails.org/classes/ActiveRecord/Locking/Pessimistic.html



### some useful ActiveRecord queries
* useful for running from console for now, similar to the sorts of info that might be exposed via REST calls as development proceeds
* things below related to status will change once status becomes a Rails enum on PreservedCopy (see #228)

#### which objects aren't in a good state?
```ruby
# example AR query
[25] pry(main)> PreservedCopy.joins(:preserved_object, :endpoint, :status).where("statuses.status_text != 'ok'").order('statuses.status_text').pluck('statuses.status_text, preserved_objects.druid, endpoints.storage_location')
```
```sql
-- example sql produced by above AR query
SELECT statuses.status_text, preserved_objects.druid, endpoints.storage_location
FROM "preserved_copies"
INNER JOIN "preserved_objects" ON "preserved_objects"."id" = "preserved_copies"."preserved_object_id"
INNER JOIN "endpoints" ON "endpoints"."id" = "preserved_copies"."endpoint_id"
INNER JOIN "statuses" ON "statuses"."id" = "preserved_copies"."status_id"
WHERE (statuses.status_text != 'ok')
ORDER BY statuses.status_text
```
```ruby
# example result, one bad object on disk 2
[["invalid_moab", "ab123cd456", "/storage_root2/storage_trunk"]]
```

#### catalog seeding just ran for the first time.  how long did it take to crawl each storage root, how many moabs does each have, what's the average moab size?
```ruby
# example AR query
[2] pry(main)> Endpoint.joins(:preserved_copies).group(:endpoint_name).order('endpoint_name asc').pluck(:endpoint_name, 'min(preserved_copies.created_at)', 'max(preserved_copies.created_at)', '(max(preserved_copies.created_at)-min(preserved_copies.created_at))', 'count(preserved_copies.id)', 'round(avg(preserved_copies.size))')
```
```sql
-- example sql produced by above AR query
SELECT "endpoints"."endpoint_name", min(preserved_copies.created_at), max(preserved_copies.created_at), (max(preserved_copies.created_at)-min(preserved_copies.created_at)), count(preserved_copies.id), round(avg(preserved_copies.size))
FROM "endpoints"
INNER JOIN "preserved_copies" ON "preserved_copies"."endpoint_id" = "endpoints"."id"
GROUP BY "endpoints"."endpoint_name"
ORDER BY endpoint_name asc
```
```ruby
# example result when there's one storage root configured, would automatically list all if there were multiple
[["storage_root2", 2017-11-18 05:49:54 UTC, 2017-11-18 06:06:50 UTC, "00:16:55.845987", 9122, 0.3132092573e10]]
```

#### how many moabs on each storage root are in a status other than 'ok'?
```ruby
# example AR query
[12] pry(main)> PreservedCopy.joins(:preserved_object, :endpoint, :status).where("statuses.status_text != 'ok'").group('statuses.status_text, endpoints.storage_location').order('statuses.status_text asc, endpoints.storage_location asc').pluck('statuses.status_text, endpoints.storage_location, count(preserved_objects.druid)')
```
```sql
-- example sql produced by above AR query
SELECT statuses.status_text, endpoints.storage_location, count(preserved_objects.druid)
FROM "preserved_copies"
INNER JOIN "preserved_objects" ON "preserved_objects"."id" = "preserved_copies"."preserved_object_id"
INNER JOIN "endpoints" ON "endpoints"."id" = "preserved_copies"."endpoint_id"
INNER JOIN "statuses" ON "statuses"."id" = "preserved_copies"."status_id"
WHERE (statuses.status_text != 'ok')
GROUP BY statuses.status_text, endpoints.storage_location
ORDER BY statuses.status_text asc, endpoints.storage_location asc
```
```ruby
# example result, some moabs that failed structural validation
[["invalid_moab", "/storage_root02/storage_trunk", 1],
 ["invalid_moab", "/storage_root03/storage_trunk", 412],
 ["invalid_moab", "/storage_root04/storage_trunk", 127],
 ["invalid_moab", "/storage_root05/storage_trunk", 72]]
```