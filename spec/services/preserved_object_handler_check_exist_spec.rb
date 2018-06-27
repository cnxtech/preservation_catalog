require 'rails_helper'
require 'services/shared_examples_preserved_object_handler'

RSpec.describe PreservedObjectHandler do
  before do
    allow(Dor::WorkflowService).to receive(:update_workflow_error_status)
  end

  let(:druid) { 'ab123cd4567' }
  let(:incoming_version) { 6 }
  let(:incoming_size) { 9876 }
  let!(:default_prez_policy) { PreservationPolicy.default_policy }
  let(:po) { PreservedObject.find_by(druid: druid) }
  let(:ep) { Endpoint.find_by(storage_location: 'spec/fixtures/storage_root01/sdr2objects') }
  let(:pc) { PreservedCopy.find_by(preserved_object: po, endpoint: ep) }
  let(:db_update_failed_prefix) { "db update failed" }
  let(:po_handler) { described_class.new(druid, incoming_version, incoming_size, ep) }

  describe '#check_existence' do
    it_behaves_like 'attributes validated', :check_existence

    context 'druid in db' do
      let(:druid) { 'bj102hs9687' }

      before do
        po = PreservedObject.create!(druid: druid, current_version: 2, preservation_policy: default_prez_policy)
        PreservedCopy.create!(
          preserved_object: po,
          version: po.current_version,
          size: 1,
          endpoint: ep,
          status: PreservedCopy::OK_STATUS # NOTE: we are pretending we checked for moab validation errs
        )
      end

      context "incoming and db versions match" do
        let(:po_handler) { described_class.new(druid, 2, 1, ep) }
        let(:version_matches_pc_msg) { "actual version (2) matches PreservedCopy db version" }

        context 'PreservedCopy' do
          context 'changed' do
            it 'last_version_audit' do
              orig = Time.current
              pc.last_version_audit = orig
              pc.save!
              po_handler.check_existence
              expect(pc.reload.last_version_audit).to be > orig
            end
            it 'updated_at' do
              orig = pc.updated_at
              po_handler.check_existence
              expect(pc.reload.updated_at).to be > orig
            end
          end
          context 'unchanged' do
            it 'status' do
              orig = pc.status
              po_handler.check_existence
              expect(pc.reload.status).to eq orig
            end
            it 'version' do
              orig = pc.version
              po_handler.check_existence
              expect(pc.reload.version).to eq orig
            end
            it 'size' do
              orig = pc.size
              po_handler.check_existence
              expect(pc.reload.size).to eq orig
            end
            it 'last_moab_validation' do
              orig = pc.last_moab_validation
              po_handler.check_existence
              expect(pc.reload.last_moab_validation).to eq orig
            end
          end
        end
        it 'PreservedObject is not updated' do
          orig = po.updated_at
          po_handler.check_existence
          expect(po.reload.updated_at).to eq orig
        end
        it_behaves_like 'calls AuditResults.report_results', :check_existence
        it 'does not validate moab' do
          expect(po_handler).not_to receive(:moab_validation_errors)
          po_handler.check_existence
        end
        context 'returns' do
          let!(:results) { po_handler.check_existence }

          it '1 result' do
            expect(results).to be_an_instance_of Array
            expect(results.size).to eq 1
          end
          it 'VERSION_MATCHES results' do
            code = AuditResults::VERSION_MATCHES
            expect(results).to include(a_hash_including(code => version_matches_pc_msg))
          end
        end
      end

      context "incoming version > db version" do
        let(:version_gt_pc_msg) { "actual version (#{incoming_version}) greater than PreservedCopy db version (2)" }

        it 'calls Stanford::StorageObjectValidator.validation_errors for moab' do
          mock_sov = instance_double(Stanford::StorageObjectValidator)
          expect(mock_sov).to receive(:validation_errors).and_return([])
          allow(Stanford::StorageObjectValidator).to receive(:new).and_return(mock_sov)
          po_handler.check_existence
        end

        context 'when moab is valid' do
          context 'PreservedCopy' do
            context 'changed' do
              before do
                allow(po_handler).to receive(:moab_validation_errors).and_return([])
                allow(po_handler).to receive(:ran_moab_validation?).and_return(true)
              end
              it 'version to incoming_version' do
                orig = pc.version
                po_handler.check_existence
                expect(pc.reload.version).to be > orig
                expect(pc.reload.version).to eq incoming_version
              end
              it 'size if supplied' do
                orig = pc.size
                po_handler.check_existence
                expect(pc.reload.size).not_to eq orig
                expect(pc.reload.size).to eq incoming_size
              end
              it 'last_moab_validation' do
                orig = Time.current
                pc.last_moab_validation = orig
                pc.save!
                po_handler.check_existence
                expect(pc.reload.last_moab_validation).to be > orig
              end
              it 'last_version_audit' do
                orig = Time.current
                pc.last_version_audit = orig
                pc.save!
                po_handler.check_existence
                expect(pc.reload.last_version_audit).to be > orig
              end
              it 'updated_at' do
                orig = pc.updated_at
                po_handler.check_existence
                expect(pc.reload.updated_at).to be > orig
              end
              it 'status becomes "ok" if it was invalid_moab (b/c after validation)' do
                pc.status = PreservedCopy::INVALID_MOAB_STATUS
                pc.save!
                po_handler.check_existence
                expect(pc.reload.status).to eq PreservedCopy::VALIDITY_UNKNOWN_STATUS
              end
            end
            context 'unchanged' do
              before do
                allow(po_handler).to receive(:moab_validation_errors).and_return([])
              end
              it 'status if former status was ok' do
                pc.status = PreservedCopy::OK_STATUS
                pc.save!
                po_handler.check_existence
                expect(pc.reload.status).to eq PreservedCopy::OK_STATUS
              end
              it 'size if incoming size is nil' do
                orig = pc.size
                po_handler = described_class.new(druid, incoming_version, nil, ep)
                po_handler.check_existence
                expect(pc.reload.size).to eq orig
              end
            end
          end
          context 'PreservedObject' do
            context 'changed' do
              before do
                allow(po_handler).to receive(:moab_validation_errors).and_return([])
              end
              it 'current_version' do
                orig = po.current_version
                po_handler.check_existence
                expect(po.reload.current_version).to be > orig
                expect(po.reload.current_version).to eq incoming_version
              end
              it 'updated_at' do
                orig = pc.updated_at
                po_handler.check_existence
                expect(pc.reload.updated_at).to be > orig
              end
            end
          end

          it_behaves_like 'calls AuditResults.report_results', :check_existence

          context 'returns' do
            let(:results) { po_handler.check_existence }

            before do
              allow(po_handler).to receive(:moab_validation_errors).and_return([])
            end
            it '1 result' do
              expect(results).to be_an_instance_of Array
              expect(results.size).to eq 1
            end
            it 'ACTUAL_VERS_GT_DB_OBJ results' do
              code = AuditResults::ACTUAL_VERS_GT_DB_OBJ
              expect(results).to include(a_hash_including(code => version_gt_pc_msg))
            end
          end
        end

        context 'when moab is invalid' do
          let(:invalid_druid) { 'xx000xx0000' }
          let(:invalid_storage_dir) { 'spec/fixtures/bad_root01/bad_moab_storage_trunk' }
          let(:invalid_ep) { Endpoint.find_by(storage_location: invalid_storage_dir) }
          let(:invalid_po_handler) { described_class.new(invalid_druid, incoming_version, incoming_size, invalid_ep) }
          let(:invalid_po) { PreservedObject.find_by(druid: invalid_druid) }
          let(:invalid_pc) { PreservedCopy.find_by(preserved_object: invalid_po) }

          before do
            # add storage root with the invalid moab to the Endpoints table
            Endpoint.find_or_create_by!(endpoint_name: 'bad_fixture_dir') do |endpoint|
              endpoint.endpoint_type = EndpointType.default_for_storage_roots
              endpoint.endpoint_node = Settings.endpoints.storage_root_defaults.endpoint_node
              endpoint.storage_location = invalid_storage_dir
            end
            # these need to be in before loop so it happens before each context below
            invalid_po = PreservedObject.create!(
              druid: invalid_druid,
              current_version: 2,
              preservation_policy: default_prez_policy
            )
            t = Time.current
            PreservedCopy.create!(
              preserved_object: invalid_po,
              version: invalid_po.current_version,
              size: 1,
              endpoint: invalid_ep,
              status: PreservedCopy::OK_STATUS, # NOTE: we are pretending we checked for moab validation errs
              last_version_audit: t,
              last_moab_validation: t
            )
          end

          context 'PreservedCopy' do
            context 'changed' do
              it 'last_version_audit' do
                orig = invalid_pc.last_version_audit
                invalid_po_handler.check_existence
                expect(invalid_pc.reload.last_version_audit).to be > orig
              end
              it 'last_moab_validation' do
                orig = invalid_pc.last_moab_validation
                invalid_po_handler.check_existence
                expect(invalid_pc.reload.last_moab_validation).to be > orig
              end
              it 'updated_at' do
                orig = invalid_pc.updated_at
                invalid_po_handler.check_existence
                expect(invalid_pc.reload.updated_at).to be > orig
              end
              it 'ensures status becomes invalid_moab from ok' do
                invalid_pc.status = PreservedCopy::OK_STATUS
                invalid_pc.save!
                invalid_po_handler.check_existence
                expect(invalid_pc.reload.status).to eq PreservedCopy::INVALID_MOAB_STATUS
              end
              it 'ensures status becomes invalid_moab from unexpected_version_on_storage' do
                invalid_pc.status = PreservedCopy::UNEXPECTED_VERSION_ON_STORAGE_STATUS
                invalid_pc.save!
                invalid_po_handler.check_existence
                expect(invalid_pc.reload.status).to eq PreservedCopy::INVALID_MOAB_STATUS
              end
            end
            context 'unchanged' do
              it 'version' do
                orig = invalid_pc.version
                invalid_po_handler.check_existence
                expect(invalid_pc.reload.version).to eq orig
              end
              it 'size' do
                orig = invalid_pc.size
                invalid_po_handler.check_existence
                expect(invalid_pc.reload.size).to eq orig
              end
            end
          end
          it 'PreservedObject is not updated' do
            orig_timestamp = invalid_po.updated_at
            invalid_po_handler.check_existence
            expect(invalid_po.reload.updated_at).to eq orig_timestamp
          end

          it_behaves_like 'calls AuditResults.report_results', :check_existence

          context 'returns' do
            let!(:results) { invalid_po_handler.check_existence }

            it '3 results' do
              expect(results).to be_an_instance_of Array
              expect(results.size).to eq 3
            end
            it 'ACTUAL_VERS_GT_DB_OBJ results' do
              code = AuditResults::ACTUAL_VERS_GT_DB_OBJ
              expect(results).to include(a_hash_including(code => version_gt_pc_msg))
            end
            it 'INVALID_MOAB result' do
              expect(results).to include(a_hash_including(AuditResults::INVALID_MOAB))
            end
          end
        end
      end

      context 'incoming version < db version' do
        let(:druid) { 'bp628nk4868' }
        let(:ep) { Endpoint.find_by(storage_location: 'spec/fixtures/storage_root02/sdr2objects') }

        it_behaves_like 'unexpected version with validation', :check_existence, 1, PreservedCopy::UNEXPECTED_VERSION_ON_STORAGE_STATUS
      end

      context 'PreservedCopy already has a status other than OK_STATUS' do
        it_behaves_like 'PreservedCopy may have its status checked when incoming_version == pc.version', :check_existence

        it_behaves_like 'PreservedCopy may have its status checked when incoming_version < pc.version', :check_existence

        context 'incoming_version > db version' do
          let(:incoming_version) { pc.version + 1 }

          it 'had OK_STATUS, version increased, should still have OK_STATUS' do
            pc.status = PreservedCopy::OK_STATUS
            pc.save!
            allow(po_handler).to receive(:moab_validation_errors).and_return([])
            po_handler.check_existence
            expect(pc.reload.status).to eq PreservedCopy::OK_STATUS
          end
          it 'had INVALID_MOAB_STATUS, was remediated, should now have VALIDITY_UNKNOWN_STATUS' do
            pc.status = PreservedCopy::INVALID_MOAB_STATUS
            pc.save!
            allow(po_handler).to receive(:moab_validation_errors).and_return([])
            po_handler.check_existence
            expect(pc.reload.status).to eq PreservedCopy::VALIDITY_UNKNOWN_STATUS
          end
          it 'had UNEXPECTED_VERSION_ON_STORAGE_STATUS, seems to have an acceptable version now' do
            pc.status = PreservedCopy::UNEXPECTED_VERSION_ON_STORAGE_STATUS
            pc.save!
            allow(po_handler).to receive(:moab_validation_errors).and_return([])
            po_handler.check_existence
            expect(pc.reload.status).to eq PreservedCopy::VALIDITY_UNKNOWN_STATUS
          end
        end
      end

      context 'PreservedCopy version does NOT match PreservedObject current_version (online Moab)' do
        before do
          po.current_version = 8
          po.save!
        end

        it_behaves_like 'PreservedObject current_version does not match online PC version', :check_existence, 3, 2, 8
      end

      context 'db update error' do
        context 'ActiveRecordError' do
          let(:result_code) { AuditResults::DB_UPDATE_FAILED }
          let(:incoming_version) { 2 }

          let(:results) do
            allow(PreservedObject).to receive(:find_by!).with(druid: druid).and_return(po)
            allow(PreservedCopy).to receive(:find_by!).with(preserved_object: po, endpoint: ep).and_return(pc)
            allow(pc).to receive(:save!).and_raise(ActiveRecord::ActiveRecordError, 'foo')
            po_handler.check_existence
          end

          context 'transaction is rolled back' do
            it 'PreservedCopy is not updated' do
              orig = pc.updated_at
              results
              expect(pc.reload.updated_at).to eq orig
            end
            it 'PreservedObject is not updated' do
              orig = po.updated_at
              results
              expect(po.reload.updated_at).to eq orig
            end
          end

          context 'DB_UPDATE_FAILED error' do
            it 'prefix' do
              expect(results).to include(a_hash_including(result_code => a_string_matching(db_update_failed_prefix)))
            end
            it 'specific exception raised' do
              expect(results).to include(a_hash_including(result_code => a_string_matching('ActiveRecord::ActiveRecordError')))
            end
            it "exception's message" do
              expect(results).to include(a_hash_including(result_code => a_string_matching('foo')))
            end
          end
        end
      end

      it 'calls PreservedCopy.save! (but not PreservedObject.save!) if the existing record is NOT altered' do
        druid = 'zy987xw6543'
        po = create :preserved_object, druid: druid
        allow(PreservedObject).to receive(:find_by!).with(druid: druid).and_return(po)
        pc = create :preserved_copy, preserved_object: po
        allow(PreservedCopy).to receive(:find_by!).with(preserved_object: po, endpoint: ep).and_return(pc)

        allow(po).to receive(:save!)
        allow(pc).to receive(:save!)
        po_handler = described_class.new(druid, 1, 1, ep)
        po_handler.check_existence
        expect(po).not_to have_received(:save!)
        expect(pc).to have_received(:save!)
      end
      it 'logs a debug message' do
        msg = "check_existence #{druid} called"
        allow(Rails.logger).to receive(:debug)
        allow(po_handler).to receive(:moab_validation_errors).and_return([])
        po_handler.check_existence
        expect(Rails.logger).to have_received(:debug).with(msg)
      end
    end

    context 'object not in db' do
      let(:exp_po_not_exist_msg) { "PreservedObject db object does not exist" }
      let(:exp_obj_created_msg) { "added object to db as it did not exist" }

      context 'presume validity and test other common behavior' do
        before do
          allow(po_handler).to receive(:moab_validation_errors).and_return([])
        end

        # FIXME: if requirements change to a single message for "object does not exist" and "created object"
        #  then this will no longer be correct?
        # NOTE: this pertains to PreservedObject
        it_behaves_like 'druid not in catalog', :check_existence

        # FIXME: if requirements change to a single message for "object does not exist" and "created object"
        #  then this will no longer be correct?
        it_behaves_like 'PreservedCopy does not exist', :check_existence
      end

      context 'adds to catalog after validation' do
        let(:valid_druid) { 'bp628nk4868' }
        let(:storage_dir) { 'spec/fixtures/storage_root02/sdr2objects' }
        let(:ep) { Endpoint.find_by(storage_location: storage_dir) }
        let(:incoming_version) { 2 }
        let(:po_handler) { described_class.new(valid_druid, incoming_version, incoming_size, ep) }

        it 'calls Stanford::StorageObjectValidator.validation_errors for moab' do
          mock_sov = instance_double(Stanford::StorageObjectValidator)
          expect(mock_sov).to receive(:validation_errors).and_return([])
          allow(Stanford::StorageObjectValidator).to receive(:new).and_return(mock_sov)
          po_handler.check_existence
        end

        context 'moab is valid' do
          it 'PreservedObject created' do
            po_args = {
              druid: valid_druid,
              current_version: incoming_version,
              preservation_policy_id: PreservationPolicy.default_policy.id
            }
            expect(PreservedObject).to receive(:create!).with(po_args).and_call_original
            po_handler.check_existence
          end
          it 'PreservedCopy created' do
            pc_args = {
              preserved_object: an_instance_of(PreservedObject), # TODO: ensure we got the preserved object we expected
              version: incoming_version,
              size: incoming_size,
              endpoint: ep,
              status: PreservedCopy::VALIDITY_UNKNOWN_STATUS, # NOTE: ensuring this particular status
              last_moab_validation: an_instance_of(ActiveSupport::TimeWithZone),
              last_version_audit: an_instance_of(ActiveSupport::TimeWithZone)
            }
            expect(PreservedCopy).to receive(:create!).with(pc_args).and_call_original
            po_handler.check_existence
          end

          it_behaves_like 'calls AuditResults.report_results', :check_existence

          context 'returns' do
            let!(:results) { po_handler.check_existence }

            it '2 results' do
              expect(results).to be_an_instance_of Array
              expect(results.size).to eq 2
            end
            it 'DB_OBJ_DOES_NOT_EXIST results' do
              code = AuditResults::DB_OBJ_DOES_NOT_EXIST
              expect(results).to include(a_hash_including(code => exp_po_not_exist_msg))
            end
            it 'CREATED_NEW_OBJECT result' do
              code = AuditResults::CREATED_NEW_OBJECT
              expect(results).to include(a_hash_including(code => exp_obj_created_msg))
            end
          end

          context 'db update error' do
            context 'ActiveRecordError' do
              let(:result_code) { AuditResults::DB_UPDATE_FAILED }
              let(:results) do
                allow(Rails.logger).to receive(:log)
                po = instance_double("PreservedObject")
                allow(PreservedObject).to receive(:create!).with(hash_including(druid: valid_druid)).and_return(po)
                allow(PreservedCopy).to receive(:create!).and_raise(ActiveRecord::ActiveRecordError, 'foo')
                po_handler.check_existence
              end

              context 'transaction is rolled back' do
                it 'PreservedCopy does not exist' do
                  expect(PreservedCopy.find_by(endpoint: ep)).to be_nil
                end
                it 'PreservedObject does not exist' do
                  expect(PreservedObject.find_by(druid: valid_druid)).to be_nil
                end
              end

              context 'DB_UPDATE_FAILED error' do
                it 'prefix' do
                  expect(results).to include(a_hash_including(result_code => a_string_matching(db_update_failed_prefix)))
                end
                it 'specific exception raised' do
                  expect(results).to include(a_hash_including(result_code => a_string_matching('ActiveRecord::ActiveRecordError')))
                end
                it "exception's message" do
                  expect(results).to include(a_hash_including(result_code => a_string_matching('foo')))
                end
              end
            end
          end
        end

        context 'moab is invalid' do
          let(:storage_dir) { 'spec/fixtures/bad_root01/bad_moab_storage_trunk' }
          let(:ep) { Endpoint.find_by(storage_location: storage_dir) }
          let(:invalid_druid) { 'xx000xx0000' }
          let(:po_handler) { described_class.new(invalid_druid, incoming_version, incoming_size, ep) }

          before do
            # add storage root with the invalid moab to the Endpoints table
            Endpoint.find_or_create_by!(endpoint_name: 'bad_fixture_dir') do |endpoint|
              endpoint.endpoint_type = EndpointType.default_for_storage_roots
              endpoint.endpoint_node = Settings.endpoints.storage_root_defaults.endpoint_node
              endpoint.storage_location = storage_dir
            end
          end

          it 'creates PreservedObject; PreservedCopy with "invalid_moab" status' do
            po_args = {
              druid: invalid_druid,
              current_version: incoming_version,
              preservation_policy_id: PreservationPolicy.default_policy.id
            }
            pc_args = {
              preserved_object: an_instance_of(PreservedObject), # TODO: ensure we got the preserved object we expected
              version: incoming_version,
              size: incoming_size,
              endpoint: ep,
              status: PreservedCopy::INVALID_MOAB_STATUS, # NOTE ensuring this particular status
              last_moab_validation: an_instance_of(ActiveSupport::TimeWithZone),
              last_version_audit: an_instance_of(ActiveSupport::TimeWithZone)
            }

            expect(PreservedObject).to receive(:create!).with(po_args).and_call_original
            expect(PreservedCopy).to receive(:create!).with(pc_args).and_call_original
            po_handler = described_class.new(invalid_druid, incoming_version, incoming_size, ep)
            po_handler.check_existence
          end

          it_behaves_like 'calls AuditResults.report_results', :check_existence

          context 'returns' do
            let!(:results) { po_handler.check_existence }

            it '3 results' do
              expect(results).to be_an_instance_of Array
              expect(results.size).to eq 3
            end
            it 'INVALID_MOAB result' do
              code = AuditResults::INVALID_MOAB
              exp_moab_errs_msg = "Invalid Moab, validation errors: [\"Missing directory: [\\\"data\\\", \\\"manifests\\\"] Version: v0001\"]"
              expect(results).to include(a_hash_including(code => exp_moab_errs_msg))
            end
            it 'DB_OBJ_DOES_NOT_EXIST results' do
              code = AuditResults::DB_OBJ_DOES_NOT_EXIST
              expect(results).to include(a_hash_including(code => exp_po_not_exist_msg))
            end
            it 'CREATED_NEW_OBJECT result' do
              code = AuditResults::CREATED_NEW_OBJECT
              expect(results).to include(a_hash_including(code => exp_obj_created_msg))
            end
          end

          context 'db update error' do
            context 'ActiveRecordError' do
              let(:result_code) { AuditResults::DB_UPDATE_FAILED }
              let(:results) do
                allow(Rails.logger).to receive(:log)

                po = instance_double("PreservedObject")
                allow(PreservedObject).to receive(:create!).with(hash_including(druid: invalid_druid)).and_return(po)
                allow(PreservedCopy).to receive(:create!).and_raise(ActiveRecord::ActiveRecordError, 'foo')
                po_handler = described_class.new(invalid_druid, incoming_version, incoming_size, ep)
                po_handler.check_existence
              end

              context 'transaction is rolled back' do
                it 'PreservedCopy does not exist' do
                  expect(PreservedCopy.find_by(endpoint: ep)).to be_nil
                end
                it 'PreservedObject does not exist' do
                  expect(PreservedObject.find_by(druid: invalid_druid)).to be_nil
                end
              end

              context 'DB_UPDATE_FAILED error' do
                it 'prefix' do
                  expect(results).to include(a_hash_including(result_code => a_string_matching(db_update_failed_prefix)))
                end
                it 'specific exception raised' do
                  expect(results).to include(a_hash_including(result_code => a_string_matching('ActiveRecord::ActiveRecordError')))
                end
                it "exception's message" do
                  expect(results).to include(a_hash_including(result_code => a_string_matching('foo')))
                end
              end
            end
          end
        end
      end
    end
  end
end
