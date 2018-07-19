require 'rails_helper'
require_relative '../../load_fixtures_helper.rb'

RSpec.describe Audit::CatalogToMoab do
  let(:last_checked_version_b4_date) { (Time.now.utc - 1.day).iso8601 }
  let(:storage_dir) { 'spec/fixtures/storage_root01/sdr2objects' }
  let(:druid) { 'bj102hs9687' }
  let(:c2m) { described_class.new(pres_copy, storage_dir) }
  let(:mock_sov) { instance_double(Stanford::StorageObjectValidator) }
  let(:po) { PreservedObject.find_by!(druid: druid) }
  let(:pres_copy) { Endpoint.find_by!(storage_location: storage_dir).preserved_copies.find_by!(preserved_object: po) }
  let(:logger_double) { instance_double(ActiveSupport::Logger, info: nil, error: nil, add: nil) }

  before do
    allow(Dor::WorkflowService).to receive(:update_workflow_error_status)
    allow(described_class).to receive(:logger).and_return(logger_double) # silence log output
  end

  include_context 'fixture moabs in db'

  context '#initialize' do
    it 'sets attributes' do
      expect(c2m.preserved_copy).to eq pres_copy
      expect(c2m.storage_dir).to eq storage_dir
      expect(c2m.druid).to eq druid
      expect(c2m.results).to be_an_instance_of AuditResults
    end
  end

  context '#check_catalog_version' do
    let(:object_dir) { "#{storage_dir}/#{DruidTools::Druid.new(druid).tree.join('/')}" }

    before { pres_copy.ok! }

    it 'instantiates Moab::StorageObject from druid and storage_dir' do
      expect(Moab::StorageObject).to receive(:new).with(druid, a_string_matching(object_dir)).and_call_original
      c2m.check_catalog_version
    end

    it 'gets the current version on disk from the Moab::StorageObject' do
      moab = instance_double(Moab::StorageObject, object_pathname: object_dir)
      allow(Moab::StorageObject).to receive(:new).with(druid, instance_of(String)).and_return(moab)
      expect(moab).to receive(:current_version_id).and_return(3)
      c2m.check_catalog_version
    end

    it 'calls PreservedCopy.update_audit_timestamps' do
      expect(pres_copy).to receive(:update_audit_timestamps).with(anything, true)
      c2m.check_catalog_version
    end

    it 'calls PreservedCopy.save!' do
      expect(pres_copy).to receive(:save!)
      c2m.check_catalog_version
    end

    it 'calls AuditResults.report_results' do
      results = instance_double(AuditResults, add_result: nil, :actual_version= => nil, :check_name= => nil)
      allow(AuditResults).to receive(:new).and_return(results)
      expect(results).to receive(:report_results)
      c2m.check_catalog_version
    end

    it 'calls online_moab_found?(druid, storage_dir)' do
      expect(c2m).to receive(:online_moab_found?)
      c2m.check_catalog_version
    end

    context 'moab is nil (exists in catalog but not online)' do
      it 'adds a MOAB_NOT_FOUND result' do
        allow(Moab::StorageObject).to receive(:new).with(druid, instance_of(String)).and_return(nil)
        results = instance_double(AuditResults, report_results: nil, :check_name= => nil)
        allow(AuditResults).to receive(:new).and_return(results)
        expect(results).to receive(:add_result).with(
          AuditResults::MOAB_NOT_FOUND, db_created_at: anything, db_updated_at: anything
        )
        expect(results).to receive(:add_result).with(
          AuditResults::PC_STATUS_CHANGED, old_status: "ok", new_status: "online_moab_not_found"
        )
        c2m.check_catalog_version
      end
      context 'updates status correctly' do
        before do
          allow(Moab::StorageObject).to receive(:new).with(druid, instance_of(String)).and_return(nil)
        end

        [
          PreservedCopy::VALIDITY_UNKNOWN_STATUS,
          PreservedCopy::OK_STATUS,
          PreservedCopy::ONLINE_MOAB_NOT_FOUND_STATUS,
          PreservedCopy::INVALID_MOAB_STATUS,
          PreservedCopy::UNEXPECTED_VERSION_ON_STORAGE_STATUS,
          PreservedCopy::INVALID_CHECKSUM_STATUS
        ].each do |orig_status|
          it "had #{orig_status}, should now have ONLINE_MOAB_NOT_FOUND_STATUS" do
            pres_copy.status = orig_status
            pres_copy.save!
            c2m.check_catalog_version
            expect(pres_copy.reload.status).to eq PreservedCopy::ONLINE_MOAB_NOT_FOUND_STATUS
          end
        end
      end
      it 'stops processing .check_catalog_version' do
        moab = instance_double(Moab::StorageObject)
        allow(Moab::StorageObject).to receive(:new).with(druid, instance_of(String)).and_return(nil)
        expect(moab).not_to receive(:current_version_id)
        c2m.check_catalog_version
      end
      context 'DB transaction handling' do
        it 'on transaction failure, completes without raising error, removes PC_STATUS_CHANGED result code' do
          allow(Moab::StorageObject).to receive(:new).with(druid, instance_of(String)).and_return(nil)
          allow(pres_copy).to receive(:save!).and_raise(ActiveRecord::ConnectionTimeoutError)
          c2m.check_catalog_version
          expect(c2m.results.result_array).to include(a_hash_including(AuditResults::MOAB_NOT_FOUND))
          expect(c2m.results.result_array).not_to include(a_hash_including(AuditResults::PC_STATUS_CHANGED))
          expect(pres_copy.reload.status).not_to eq PreservedCopy::ONLINE_MOAB_NOT_FOUND_STATUS
        end
      end
    end

    context 'preserved_copy version != current_version of preserved_object' do
      it 'adds a PC_PO_VERSION_MISMATCH result and finishes processing' do
        pres_copy.version = 666
        results = instance_double(AuditResults, report_results: nil, :check_name= => nil)
        allow(AuditResults).to receive(:new).and_return(results)
        expect(results).to receive(:add_result).with(
          AuditResults::PC_PO_VERSION_MISMATCH,
          pc_version: pres_copy.version,
          po_version: pres_copy.preserved_object.current_version
        )
        expect(Moab::StorageObject).not_to receive(:new).with(druid, a_string_matching(object_dir)).and_call_original
        c2m.check_catalog_version
      end
      it 'calls AuditResults.report_results' do
        pres_copy.version = 666
        results = instance_double(AuditResults, report_results: nil, :check_name= => nil)
        allow(results).to receive(:add_result)
        allow(AuditResults).to receive(:new).and_return(results)
        expect(results).to receive(:report_results)
        c2m.check_catalog_version
      end
    end

    context 'catalog version == moab version (happy path)' do
      it 'adds a VERSION_MATCHES result' do
        results = instance_double(AuditResults, report_results: nil, :actual_version= => nil, :check_name= => nil)
        allow(AuditResults).to receive(:new).and_return(results)
        expect(results).to receive(:add_result).with(AuditResults::VERSION_MATCHES, 'PreservedCopy')
        c2m.check_catalog_version
      end

      context 'check whether PreservedCopy already has a status other than OK_STATUS, re-check status if so;' do
        it "had OK_STATUS, should keep OK_STATUS" do
          pres_copy.ok!
          allow(c2m).to receive(:moab_validation_errors).and_return([])
          c2m.check_catalog_version
          expect(pres_copy.reload).to be_ok
        end

        [
          PreservedCopy::VALIDITY_UNKNOWN_STATUS,
          PreservedCopy::ONLINE_MOAB_NOT_FOUND_STATUS,
          PreservedCopy::INVALID_MOAB_STATUS,
          PreservedCopy::UNEXPECTED_VERSION_ON_STORAGE_STATUS
        ].each do |orig_status|
          it "had #{orig_status}, should now have validity_unknown" do
            pres_copy.status = orig_status
            pres_copy.save!
            allow(c2m).to receive(:moab_validation_errors).and_return([])
            c2m.check_catalog_version
            expect(pres_copy.reload).to be_validity_unknown
          end
        end

        # PreservedCopy::OK_STATUS intentionally omitted, since we don't check status on disk
        # if versions match
        [
          PreservedCopy::VALIDITY_UNKNOWN_STATUS,
          PreservedCopy::ONLINE_MOAB_NOT_FOUND_STATUS,
          PreservedCopy::INVALID_MOAB_STATUS,
          PreservedCopy::UNEXPECTED_VERSION_ON_STORAGE_STATUS
        ].each do |orig_status|
          it "had #{orig_status}, should now have INVALID_MOAB_STATUS" do
            pres_copy.status = orig_status
            pres_copy.save!
            allow(c2m).to receive(:moab_validation_errors).and_return(
              [{ Moab::StorageObjectValidator::MISSING_DIR => 'err msg' }]
            )
            c2m.check_catalog_version
            expect(pres_copy.reload.status).to eq PreservedCopy::INVALID_MOAB_STATUS
          end
        end

        context 'started with INVALID_CHECKSUM_STATUS' do
          before { pres_copy.invalid_checksum! }

          it 'remains in INVALID_CHECKSUM_STATUS' do
            allow(c2m).to receive(:moab_validation_errors).and_return(
              [{ Moab::StorageObjectValidator::MISSING_DIR => 'err msg' }]
            )
            c2m.check_catalog_version
            expect(pres_copy.reload.status).to eq PreservedCopy::INVALID_CHECKSUM_STATUS
          end

          it 'has an AuditResults entry indicating inability to check the given status' do
            c2m.check_catalog_version
            expect(c2m.results.contains_result_code?(AuditResults::UNABLE_TO_CHECK_STATUS)).to eq true
          end
        end
      end
    end

    context 'catalog version < moab version' do
      before do
        moab = instance_double(Moab::StorageObject, size: 666, object_pathname: object_dir)
        allow(Moab::StorageObject).to receive(:new).with(druid, instance_of(String)).and_return(moab)
        allow(moab).to receive(:current_version_id).and_return(4)
      end

      it 'calls PreservedObjectHandler.update_version_after_validation' do
        pohandler = instance_double(PreservedObjectHandler)
        expect(PreservedObjectHandler).to receive(:new).and_return(pohandler)
        expect(pohandler).to receive(:update_version_after_validation)
        c2m.check_catalog_version
      end

      context 'runs validations other than checksum' do
        context 'no validation errors' do
          [
            PreservedCopy::VALIDITY_UNKNOWN_STATUS,
            PreservedCopy::OK_STATUS,
            PreservedCopy::ONLINE_MOAB_NOT_FOUND_STATUS,
            PreservedCopy::INVALID_MOAB_STATUS,
            PreservedCopy::UNEXPECTED_VERSION_ON_STORAGE_STATUS
          ].each do |orig_status|
            it "#{orig_status} changes to validity_unknown" do
              pres_copy.status = orig_status
              pres_copy.save!
              allow(mock_sov).to receive(:validation_errors).and_return([])
              allow(Stanford::StorageObjectValidator).to receive(:new).and_return(mock_sov)
              c2m.check_catalog_version
              expect(pres_copy.reload).to be_validity_unknown
            end
          end
        end

        context 'finds validation errors' do
          [
            PreservedCopy::VALIDITY_UNKNOWN_STATUS,
            PreservedCopy::OK_STATUS,
            PreservedCopy::ONLINE_MOAB_NOT_FOUND_STATUS,
            PreservedCopy::UNEXPECTED_VERSION_ON_STORAGE_STATUS
          ].each do |orig_status|
            it "#{orig_status} changes to INVALID_MOAB_STATUS" do
              pres_copy.status = orig_status
              pres_copy.save!
              allow(mock_sov).to receive(:validation_errors).and_return(
                [{ Moab::StorageObjectValidator::MISSING_DIR => 'err msg' }]
              )
              allow(Stanford::StorageObjectValidator).to receive(:new).and_return(mock_sov)
              c2m.check_catalog_version
              expect(pres_copy.reload.status).to eq PreservedCopy::INVALID_MOAB_STATUS
            end
          end
          it "invalid_moab changes to validity_unknown (due to newer version not checksum validated)" do
            pres_copy.invalid_moab!
            allow(mock_sov).to receive(:validation_errors).and_return(
              [{ Moab::StorageObjectValidator::MISSING_DIR => 'err msg' }]
            )
            allow(Stanford::StorageObjectValidator).to receive(:new).and_return(mock_sov)
            c2m.check_catalog_version
            expect(pres_copy.reload.status).to eq PreservedCopy::VALIDITY_UNKNOWN_STATUS
          end
        end

        context 'had INVALID_CHECKSUM_STATUS (which C2M cannot validate)' do
          before do
            allow(Stanford::StorageObjectValidator).to receive(:new).and_return(mock_sov)
            pres_copy.invalid_checksum!
          end

          it 'may have moab validation errors, but should still have INVALID_CHECKSUM_STATUS' do
            allow(mock_sov).to receive(:validation_errors).and_return(
              [{ Moab::StorageObjectValidator::MISSING_DIR => 'err msg' }]
            )
            c2m.check_catalog_version
            expect(pres_copy.reload.status).to eq PreservedCopy::INVALID_CHECKSUM_STATUS
          end

          it 'would have no moab validation errors, but should still have INVALID_CHECKSUM_STATUS' do
            allow(mock_sov).to receive(:validation_errors).and_return([])
            c2m.check_catalog_version
            expect(pres_copy.reload.status).to eq PreservedCopy::INVALID_CHECKSUM_STATUS
          end

          it 'has an AuditResults entry indicating inability to check the given status' do
            c2m.check_catalog_version
            expect(c2m.results.contains_result_code?(AuditResults::UNABLE_TO_CHECK_STATUS)).to eq true
          end
        end
      end
    end

    context 'catalog version > moab version' do
      before do
        moab = instance_double(Moab::StorageObject, size: 666, object_pathname: object_dir, current_version_id: 2)
        allow(Moab::StorageObject).to receive(:new).with(druid, instance_of(String)).and_return(moab)
      end

      it 'adds an UNEXPECTED_VERSION result' do
        results = instance_double(AuditResults, report_results: nil, :actual_version= => nil, :check_name= => nil)
        expect(results).to receive(:add_result).with(
          AuditResults::UNEXPECTED_VERSION, db_obj_name: 'PreservedCopy', db_obj_version: pres_copy.version
        )
        allow(results).to receive(:add_result).with(any_args)
        allow(AuditResults).to receive(:new).and_return(results)
        c2m.check_catalog_version
      end

      it 'calls Stanford::StorageObjectValidator.validation_errors for moab' do
        expect(mock_sov).to receive(:validation_errors).and_return([])
        allow(Stanford::StorageObjectValidator).to receive(:new).and_return(mock_sov)
        c2m.check_catalog_version
      end
      it 'valid moab sets status to UNEXPECTED_VERSION_ON_STORAGE_STATUS' do
        orig = pres_copy.status
        c2m.check_catalog_version
        new_status = pres_copy.reload.status
        expect(new_status).not_to eq orig
        expect(new_status).to eq PreservedCopy::UNEXPECTED_VERSION_ON_STORAGE_STATUS
      end
      context 'invalid moab' do
        before do
          allow(mock_sov).to receive(:validation_errors).and_return([foo: 'error message'])
          allow(Stanford::StorageObjectValidator).to receive(:new).and_return(mock_sov)
        end
        it 'sets status to INVALID_MOAB_STATUS' do
          orig = pres_copy.status
          c2m.check_catalog_version
          new_status = pres_copy.reload.status
          expect(new_status).not_to eq orig
          expect(new_status).to eq PreservedCopy::INVALID_MOAB_STATUS
        end
        it 'adds an INVALID_MOAB result' do
          results = instance_double(AuditResults, report_results: nil, :actual_version= => nil, :check_name= => nil)
          expect(results).to receive(:add_result).with(AuditResults::INVALID_MOAB, anything)
          allow(results).to receive(:add_result).with(any_args)
          allow(AuditResults).to receive(:new).and_return(results)
          c2m.check_catalog_version
        end
      end
      it 'adds a PC_STATUS_CHANGED result' do
        results = instance_double(AuditResults, report_results: nil, :actual_version= => nil, :check_name= => nil)
        expect(results).to receive(:add_result).with(
          AuditResults::PC_STATUS_CHANGED, a_hash_including(:old_status, :new_status)
        )
        allow(results).to receive(:add_result).with(any_args)
        allow(AuditResults).to receive(:new).and_return(results)
        c2m.check_catalog_version
      end

      context 'check whether PreservedCopy already has a status other than OK_STATUS, re-check status if possible' do
        [
          PreservedCopy::VALIDITY_UNKNOWN_STATUS,
          PreservedCopy::OK_STATUS,
          PreservedCopy::ONLINE_MOAB_NOT_FOUND_STATUS,
          PreservedCopy::INVALID_MOAB_STATUS,
          PreservedCopy::UNEXPECTED_VERSION_ON_STORAGE_STATUS
        ].each do |orig_status|
          it "had #{orig_status}, should now have EXPECTED_VERS_NOT_FOUND_ON_STORAGE_STATUS" do
            pres_copy.status = orig_status
            pres_copy.save!
            allow(c2m).to receive(:moab_validation_errors).and_return([])
            c2m.check_catalog_version
            expect(pres_copy.reload.status).to eq PreservedCopy::UNEXPECTED_VERSION_ON_STORAGE_STATUS
          end
        end

        [
          PreservedCopy::VALIDITY_UNKNOWN_STATUS,
          PreservedCopy::OK_STATUS,
          PreservedCopy::ONLINE_MOAB_NOT_FOUND_STATUS,
          PreservedCopy::INVALID_MOAB_STATUS,
          PreservedCopy::UNEXPECTED_VERSION_ON_STORAGE_STATUS
        ].each do |orig_status|
          it "had #{orig_status}, should now have INVALID_MOAB_STATUS" do
            pres_copy.status = orig_status
            pres_copy.save!
            allow(c2m).to receive(:moab_validation_errors).and_return(
              [{ Moab::StorageObjectValidator::MISSING_DIR => 'err msg' }]
            )
            c2m.check_catalog_version
            expect(pres_copy.reload.status).to eq PreservedCopy::INVALID_MOAB_STATUS
          end
        end

        context 'had INVALID_CHECKSUM_STATUS, which C2M cannot validate' do
          before do
            allow(Stanford::StorageObjectValidator).to receive(:new).and_return(mock_sov)
            pres_copy.invalid_checksum!
          end

          it 'may have moab validation errors, but should still have INVALID_CHECKSUM_STATUS' do
            allow(mock_sov).to receive(:validation_errors).and_return(
              [{ Moab::StorageObjectValidator::MISSING_DIR => 'err msg' }]
            )
            c2m.check_catalog_version
            expect(pres_copy.reload.status).to eq PreservedCopy::INVALID_CHECKSUM_STATUS
          end

          it 'would have no moab validation errors, but should still have INVALID_CHECKSUM_STATUS' do
            allow(mock_sov).to receive(:validation_errors).and_return([])
            c2m.check_catalog_version
            expect(pres_copy.reload.status).to eq PreservedCopy::INVALID_CHECKSUM_STATUS
          end

          it 'has an AuditResults entry indicating inability to check the given status' do
            c2m.check_catalog_version
            expect(c2m.results.contains_result_code?(AuditResults::UNABLE_TO_CHECK_STATUS)).to eq true
          end
        end
      end
    end

    context 'moab found on disk' do
      # use the same setup as 'catalog version > moab version', since we know that should
      # lead to an update_status(PreservedCopy::UNEXPECTED_VERSION_ON_STORAGE_STATUS) call
      before do
        moab = instance_double(Moab::StorageObject, size: 666, object_pathname: object_dir)
        allow(Moab::StorageObject).to receive(:new).with(druid, instance_of(String)).and_return(moab)
        allow(moab).to receive(:current_version_id).and_return(2)
      end

      context 'DB transaction handling' do
        it 'on transaction failure, completes without raising error, removes PC_STATUS_CHANGED result code' do
          allow(pres_copy).to receive(:save!).and_raise(ActiveRecord::ConnectionTimeoutError)
          c2m.check_catalog_version
          expect(c2m.results.result_array).to include(a_hash_including(AuditResults::UNEXPECTED_VERSION))
          expect(c2m.results.result_array).not_to include(a_hash_including(AuditResults::PC_STATUS_CHANGED))
          expect(pres_copy.reload.status).not_to eq PreservedCopy::UNEXPECTED_VERSION_ON_STORAGE_STATUS
        end
      end
    end
  end
end
