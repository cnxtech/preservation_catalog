FactoryBot.define do
  factory :preserved_copy do
    version 1
    status 'ok'
    size 231
    endpoint { "fake endpoint" }
    preserved_object
  end
end