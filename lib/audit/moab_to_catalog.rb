require 'profiler.rb'

##
# finds Moab objects on a single Moab storage_dir and interacts with Catalog (db)
#   according to method called
class MoabToCatalog

  # NOTE: shameless green! code duplication with seed_catalog_for_dir
  def self.check_existence_for_dir(storage_dir)
    start_msg = "#{Time.now.utc.iso8601} M2C check_existence starting for '#{storage_dir}'"
    puts start_msg
    Rails.logger.info start_msg
    results = []
    endpoint = Endpoint.find_by!(storage_location: storage_dir)
    Stanford::MoabStorageDirectory.find_moab_paths(storage_dir) do |druid, path, _path_match_data|
      moab = Moab::StorageObject.new(druid, path)
      po_handler = PreservedObjectHandler.new(druid, moab.current_version_id, moab.size, endpoint)
      results.concat po_handler.check_existence
    end
    end_msg = "#{Time.now.utc.iso8601} M2C check_existence ended for '#{storage_dir}'"
    puts end_msg
    Rails.logger.info end_msg
    results
  end

  def self.check_existence_for_dir_profiled(storage_dir)
    profiler = Profiler.new
    profiler.prof { check_existence_for_dir(storage_dir) }
    profiler.print_results_flat('M2C_check_existence_for_dir')
  end

  # NOTE: shameless green! code duplication with check_existence_for_dir
  def self.seed_catalog_for_dir(storage_dir)
    start_msg = "#{Time.now.utc.iso8601} Seeding starting for '#{storage_dir}'"
    puts start_msg
    Rails.logger.info start_msg
    results = []
    endpoint = Endpoint.find_by!(storage_location: storage_dir)
    Stanford::MoabStorageDirectory.find_moab_paths(storage_dir) do |druid, path, _path_match_data|
      moab = Moab::StorageObject.new(druid, path)
      po_handler = PreservedObjectHandler.new(druid, moab.current_version_id, moab.size, endpoint)
      results << po_handler.create_after_validation
    end
    end_msg = "#{Time.now.utc.iso8601} Seeding ended for '#{storage_dir}'"
    puts end_msg
    Rails.logger.info end_msg
    results
  end

  # Shameless green. In order to run several seed "jobs" in parallel, we would have to refactor.
  def self.seed_catalog_for_all_storage_roots
    start_msg = "#{Time.now.utc.iso8601} Seeding for all storage roots starting"
    puts start_msg
    Rails.logger.info start_msg
    Settings.moab.storage_roots.each do |_strg_root_name, strg_root_location|
      seed_catalog_for_dir("#{strg_root_location}/#{Settings.moab.storage_trunk}")
    end
    end_msg = "#{Time.now.utc.iso8601} Seeding for all storage roots ended'"
    puts end_msg
    Rails.logger.info end_msg
  end

  def self.seed_catalog_for_all_storage_roots_profiled
    profiler = Profiler.new
    profiler.prof { seed_catalog_for_all_storage_roots }
    profiler.print_results_flat('seed_catalog_for_all_storage_roots')
  end

  # Shameless green. Code duplication with seed_catalog_for_all_storage_roots
  def self.check_existence_for_all_storage_roots
    start_msg = "#{Time.now.utc.iso8601} M2C check_existence for all storage roots starting'"
    puts start_msg
    Rails.logger.info start_msg
    Settings.moab.storage_roots.each do |_strg_root_name, strg_root_location|
      check_existence_for_dir("#{strg_root_location}/#{Settings.moab.storage_trunk}")
    end
    end_msg = "#{Time.now.utc.iso8601} M2C check_existence for all storage roots ended'"
    puts end_msg
    Rails.logger.info end_msg
  end

  def self.check_existence_for_all_storage_roots_profiled
    profiler = Profiler.new
    profiler.prof { check_existence_for_all_storage_roots }
    profiler.print_results_flat('M2C_check_existence_for_all_storage_roots')
  end

  def self.drop_endpoint(endpoint_name)
    ApplicationRecord.transaction do
      PreservedCopy.joins(:endpoint).where(
        "endpoints.endpoint_name = :endpoint_name",
        endpoint_name: endpoint_name.to_s
      ).destroy_all
      PreservedObject.left_outer_joins(:preserved_copies).where(preserved_copies: { id: nil }).destroy_all
    end
  end

  def self.populate_endpoint(endpoint_name)
    endpoint = Endpoint.find_by!(endpoint_name: endpoint_name)
    MoabToCatalog.seed_catalog_for_dir(endpoint.storage_location)
  end

  def self.populate_endpoint_profiled(endpoint_name)
    profiler = Profiler.new
    profiler.prof { populate_endpoint(endpoint_name) }
    profiler.print_results_flat('populate_endpoint')
  end
end
