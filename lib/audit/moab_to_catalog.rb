require 'profiler.rb'

##
# finds Moab objects on a single Moab storage_dir and interacts with Catalog (db)
#   according to method called
class MoabToCatalog

  # NOTE: shameless green! code duplication with seed_catalog
  def self.check_existence(storage_dir, expect_to_create=false)
    results = []
    endpoint = Endpoint.find_by!(storage_location: storage_dir)
    Stanford::MoabStorageDirectory.find_moab_paths(storage_dir) do |druid, path, _path_match_data|
      moab = Moab::StorageObject.new(druid, path)
      po_handler = PreservedObjectHandler.new(druid, moab.current_version_id, moab.size, endpoint)
      if PreservedObject.exists?(druid: druid)
        results << po_handler.confirm_version
      else
        Rails.logger.error "druid: #{druid} expected to exist in catalog but was not found"
        results << po_handler.create if expect_to_create
      end
    end
    results
  end

  # NOTE: shameless green! code duplication with check_existence
  def self.seed_catalog(storage_dir)
    results = []
    endpoint = Endpoint.find_by!(storage_location: storage_dir)
    Stanford::MoabStorageDirectory.find_moab_paths(storage_dir) do |druid, path, _path_match_data|
      moab = Moab::StorageObject.new(druid, path)
      po_handler = PreservedObjectHandler.new(druid, moab.current_version_id, moab.size, endpoint)
      if PreservedObject.exists?(druid: druid)
        Rails.logger.error "druid: #{druid} NOT expected to exist in catalog but was found"
      else
        results << po_handler.create_after_validation
      end
    end
    results
  end

  # Shameless green. In order to run several seed "jobs" in parallel, we would have to refactor.
  def self.seed_from_disk
    Settings.moab.storage_roots.each do |strg_root_name, strg_root_location|
      start_msg = "#{Time.now.utc.iso8601} Seeding starting for '#{strg_root_name}' at #{strg_root_location}"
      puts start_msg
      Rails.logger.info start_msg
      seed_catalog("#{strg_root_location}/#{Settings.moab.storage_trunk}")
      end_msg = "#{Time.now.utc.iso8601} Seeding ended for '#{strg_root_name}' at #{strg_root_location}"
      puts end_msg
      Rails.logger.info end_msg
    end
  end

  def self.seed_from_disk_with_profiling
    profiler = Profiler.new
    profiler.prof { seed_from_disk }
    profiler.print_results_flat('profile-flat-seed_from_disk')
  end

  # Shameless green. Code duplication with seed_from_disk
  def self.check_existence_from_disk
    Settings.moab.storage_roots.each do |strg_root_name, strg_root_location|
      start_msg = "#{Time.now.utc.iso8601} Check_existence starting for '#{strg_root_name}' at #{strg_root_location}"
      puts start_msg
      Rails.logger.info start_msg
      check_existence("#{strg_root_location}/#{Settings.moab.storage_trunk}")
      end_msg = "#{Time.now.utc.iso8601} Check_existence ended for '#{strg_root_name}' at #{strg_root_location}"
      puts end_msg
      Rails.logger.info end_msg
    end
  end
end
