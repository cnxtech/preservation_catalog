require 'rails_helper'
require 'services/shared_examples_preserved_object_handler'

RSpec.describe PreservedObjectHandler do
  let(:druid) { 'ab123cd4567' }
  let(:incoming_version) { 6 }
  let(:incoming_size) { 9876 }
  let(:default_prez_policy) { PreservationPolicy.default_policy }
  let(:ep) { Endpoint.find_by!(storage_location: 'spec/fixtures/storage_root01/moab_storage_trunk') }
  let(:pc) { PreservedCopy.find_by!(preserved_object: po, endpoint: ep) }
  let(:po) { PreservedObject.find_by!(druid: druid) }
  let(:po2) { PreservedObject.create!(druid: druid, current_version: 2, preservation_policy: default_prez_policy) }
  let(:db_update_failed_prefix) { "db update failed" }

  let(:po_handler) { described_class.new(druid, incoming_version, incoming_size, ep) }

  describe '#update_version' do
    it_behaves_like 'attributes validated', :update_version

    context 'in Catalog' do
      before do
        @pc = PreservedCopy.create!(
          preserved_object: po2,
          version: po2.current_version,
          size: 1,
          endpoint: ep,
          status: 'ok', # pretending we checked for moab validation errs at create time
          last_version_audit: Time.current,
          last_moab_validation: Time.current
        )
      end

      context 'incoming version newer than catalog versions (both) (happy path)' do
        context 'PreservedCopy' do
          context 'changed' do
            it "version becomes incoming_version" do
              expect { po_handler.update_version && pc.reload }.to change { pc.version }.to(incoming_version)
            end
            it 'last_version_audit' do
              orig = pc.last_version_audit
              po_handler.update_version
              expect(pc.reload.last_version_audit).to be > orig
            end
            it 'size if supplied' do
              expect { po_handler.update_version && pc.reload }.to change { pc.size }.to(incoming_size)
            end
          end
          context 'unchanged' do
            it 'size if incoming size is nil' do
              po_handler = described_class.new(druid, incoming_version, nil, ep)
              expect { po_handler.update_version }.not_to change { pc.reload.size }
            end
            it 'status' do
              expect { po_handler.update_version }.not_to change { pc.reload.status }
              skip 'is there a scenario when status should change here?  See #431'
            end
            it 'last_moab_validation' do
              expect { po_handler.update_version }.not_to change { pc.reload.last_moab_validation }
            end
          end
        end

        context 'PreservedObject changed' do
          it "current_version becomes incoming version" do
            expect { po_handler.update_version }.to change { po.reload.current_version }.to(incoming_version)
          end
        end
        it_behaves_like 'calls AuditResults.report_results', :update_version

        context 'returns' do
          let(:results) { po_handler.update_version }

          it '1 result' do
            expect(results).to be_an_instance_of Array
            expect(results.size).to eq 1
          end
          it 'ACTUAL_VERS_GT_DB_OBJ results' do
            code = AuditResults::ACTUAL_VERS_GT_DB_OBJ
            version_gt_pc_msg = "actual version (#{incoming_version}) greater than PreservedCopy db version (2)"
            expect(results).to include(a_hash_including(code => version_gt_pc_msg))
          end
        end
      end

      context 'PreservedCopy and PreservedObject versions do not match' do
        before do
          @pc.version = @pc.version + 1
          @pc.save!
        end

        it_behaves_like 'PreservedObject current_version does not match online PC version', :update_version, 3, 3, 2
      end

      context 'incoming version same as catalog versions (both)' do
        it_behaves_like 'unexpected version', :update_version, 2, PreservedCopy::OK_STATUS
      end

      context 'incoming version lower than catalog versions (both)' do
        it_behaves_like 'unexpected version', :update_version, 1
      end

      context 'db update error' do
        let(:result_code) { AuditResults::DB_UPDATE_FAILED }
        let(:results) { po_handler.update_version }
        let(:po) { build(:preserved_object) }
        let(:pc) { build(:preserved_copy, endpoint: ep) }

        before do
          allow(Rails.logger).to receive(:log)
          allow(PreservedObject).to receive(:find_by!).with(druid: druid).and_return(po)
          allow(PreservedCopy).to receive(:find_by!).with(preserved_object: po, endpoint: ep).and_return(pc)
        end

        context 'PreservedCopy ActiveRecordError' do
          before { allow(pc).to receive(:save!).and_raise(ActiveRecord::ActiveRecordError, 'foo') }

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

        context 'PreservedObject ActiveRecordError' do
          let(:po) { build(:preserved_object, current_version: 5) }
          # let(:pc) { build(:preserved_copy, version: po.current_version) } # would prefer this, but hit snags
          let(:pc) do
            pres_copy = instance_double(PreservedCopy, version: 5, changed?: true, matches_po_current_version?: true, status: 'ok')
            allow(pres_copy).to receive(:upd_audstamps_version_size).with(boolean, incoming_version, incoming_size)
            allow(pres_copy).to receive(:status=)
            allow(pres_copy).to receive(:update_audit_timestamps)
            allow(pres_copy).to receive(:save!)
            pres_copy
          end

          before { allow(po).to receive(:save!).and_raise(ActiveRecord::ActiveRecordError, 'foo') }

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

      it 'calls PreservedObject.save! and PreservedCopy.save! if the records are altered' do
        po = build(:preserved_object)
        pc = build(:preserved_copy, endpoint: ep)
        allow(PreservedObject).to receive(:find_by).with(druid: druid).and_return(po)
        allow(PreservedCopy).to receive(:find_by).with(preserved_object: po, endpoint: ep).and_return(pc)
        expect(po).to receive(:save!)
        expect(pc).to receive(:save!)
        po_handler.update_version
      end

      it 'does not call PreservedObject.save when PreservedCopy only has timestamp updates' do
        po = build(:preserved_object)
        pc = build(:preserved_copy, endpoint: ep)
        allow(PreservedObject).to receive(:find_by).with(druid: druid).and_return(po)
        allow(PreservedCopy).to receive(:find_by).with(preserved_object: po, endpoint: ep).and_return(pc)
        po_handler = described_class.new(druid, 1, 1, ep)
        expect(pc).to receive(:save!)
        expect(po).not_to receive(:save!)
        po_handler.update_version
      end

      it 'logs a debug message' do
        allow(Rails.logger).to receive(:debug)
        po_handler.update_version
        expect(Rails.logger).to have_received(:debug).with("update_version #{druid} called")
      end
    end

    it_behaves_like 'druid not in catalog', :update_version

    it_behaves_like 'PreservedCopy does not exist', :update_version
  end

  describe '#update_version_after_validation' do
    let(:druid) { 'bp628nk4868' }
    let(:ep) { Endpoint.find_by(storage_location: 'spec/fixtures/storage_root02/moab_storage_trunk') }

    it_behaves_like 'attributes validated', :update_version_after_validation

    it 'calls Stanford::StorageObjectValidator.validation_errors for moab' do
      mock_sov = instance_double(Stanford::StorageObjectValidator, validation_errors: [])
      allow(Stanford::StorageObjectValidator).to receive(:new).and_return(mock_sov)
      po_handler.update_version_after_validation
    end

    context 'in Catalog' do
      context 'when moab is valid' do
        let(:po) { PreservedObject.create!(druid: druid, current_version: 2, preservation_policy: default_prez_policy) }

        before do
          t = Time.current
          PreservedCopy.create!(
            preserved_object: po,
            version: po.current_version,
            size: 1,
            endpoint: ep,
            status: PreservedCopy::OK_STATUS, # NOTE: pretending we checked for moab validation errs at create time
            last_version_audit: t,
            last_moab_validation: t
          )
        end

        context 'PreservedCopy' do
          context 'changed' do
            it 'last_version_audit' do
              orig = pc.last_version_audit
              po_handler.update_version_after_validation
              expect(pc.reload.last_version_audit).to be > orig
            end
            it 'last_moab_validation' do
              orig = pc.last_moab_validation
              po_handler.update_version_after_validation
              expect(pc.reload.last_moab_validation).to be > orig
            end
            it 'version becomes incoming_version' do
              expect { po_handler.update_version_after_validation && pc.reload }.to change { pc.version }.to(incoming_version)
            end
            it 'size if supplied' do
              expect { po_handler.update_version_after_validation && pc.reload }.to change { pc.size }.to(incoming_size)
            end
          end
          context 'unchanged' do
            it 'size if incoming size is nil' do
              po_handler = described_class.new(druid, incoming_version, nil, ep)
              expect { po_handler.update_version_after_validation }.not_to change { pc.reload.size }
            end
            it 'status' do
              expect { po_handler.update_version_after_validation }.not_to change { pc.reload.status }
              skip 'is there a scenario when status should change here?  See #431'
            end
          end
        end

        context 'PreservedObject changed' do
          it 'current_version' do
            orig = po.current_version
            po_handler.update_version_after_validation
            expect(po.reload.current_version).to eq po_handler.incoming_version
            expect(po.current_version).to be > orig
          end
        end

        it 'calls #update_online_version with validated = true and status = "ok"' do
          expect(po_handler).to receive(:update_online_version).with(PreservedCopy::OK_STATUS).and_call_original
          po_handler.update_version_after_validation
          skip 'test is weak b/c we only indirectly show the effects of #update_online_version in #update_version specs'
        end

        it 'updates PreservedCopy status to "ok" if it was "moab_invalid"' do
          pc.invalid_moab!
          po_handler.update_version_after_validation
          expect(pc.reload.status).to eq 'ok'
        end
      end

      context 'when moab is invalid' do
        let(:druid) { 'xx000xx0000' }
        let(:storage_dir) { 'spec/fixtures/bad_root01/bad_moab_storage_trunk' }
        let(:ep) { Endpoint.find_by(storage_location: storage_dir) }

        before do
          Endpoint.find_or_create_by!(endpoint_name: 'bad_fixture_dir') do |endpoint|
            endpoint.endpoint_type = Endpoint.default_storage_root_endpoint_type
            endpoint.endpoint_node = Settings.endpoints.storage_root_defaults.endpoint_node
            endpoint.storage_location = storage_dir
            endpoint.recovery_cost = Settings.endpoints.storage_root_defaults.recovery_cost
          end
          t = Time.current
          PreservedCopy.create!(
            preserved_object: po2,
            version: po2.current_version,
            size: 1,
            endpoint: ep,
            status: PreservedCopy::OK_STATUS, # pretending we checked for moab validation errs at create time
            last_version_audit: t,
            last_moab_validation: t
          )
        end

        context 'PreservedCopy' do
          context 'changed' do
            it 'last_moab_validation' do
              orig = pc.last_moab_validation
              po_handler.update_version_after_validation
              expect(pc.reload.last_moab_validation).to be > orig
            end
            it 'status' do
              orig = pc.status
              po_handler.update_version_after_validation
              expect(pc.reload.status).to eq PreservedCopy::INVALID_MOAB_STATUS
              expect(pc.status).not_to eq orig
            end
          end
          context 'unchanged' do
            it 'version' do
              expect { po_handler.update_version_after_validation }.not_to change { pc.reload.version }
            end
            it 'size' do
              expect { po_handler.update_version_after_validation }.not_to change { pc.reload.size }
            end
            it 'last_version_audit' do
              expect { po_handler.update_version_after_validation }.not_to change { pc.reload.last_version_audit }
            end
          end
        end
        context 'PreservedObject' do
          context 'unchanged' do
            it 'current_version' do
              expect { po_handler.update_version_after_validation }.not_to change { po.reload.current_version }
            end
          end
        end

        it 'ensures PreservedCopy status is invalid' do
          pc.ok!
          po_handler.update_version_after_validation
          expect(pc.reload.status).to eq PreservedCopy::INVALID_MOAB_STATUS
        end

        it 'logs a debug message' do
          msg = "update_version_after_validation #{druid} called"
          allow(Rails.logger).to receive(:debug)
          po_handler.update_version_after_validation
          expect(Rails.logger).to have_received(:debug).with(msg)
        end

        it 'does not call PreservedObject.save! when PreservedCopy only has timestamp updates' do
          po = build(:preserved_object)
          pc = build(:preserved_copy)
          allow(PreservedObject).to receive(:find_by).with(druid: druid).and_return(po)
          allow(PreservedCopy).to receive(:find_by).with(preserved_object: po, endpoint: ep).and_return(pc)
          allow(po_handler).to receive(:moab_validation_errors).and_return(['foo'])
          expect(pc).to receive(:save!)
          expect(po).not_to receive(:save!)
          po_handler.update_version_after_validation
        end

        context 'incoming version newer than catalog versions (both) (happy path)' do
          it 'calls #update_online_version with validated = true and status = "invalid_moab"' do
            expect(po_handler).to receive(:update_online_version).with(true, PreservedCopy::INVALID_MOAB_STATUS).and_call_original
            po_handler.update_version_after_validation
            skip 'test is weak b/c we only indirectly show the effects of #update_online_version in #update_version specs'
          end
        end

        context 'PreservedCopy and PreservedObject versions do not match' do
          before do
            pc.version = pc.version + 1
            pc.save!
          end

          it_behaves_like 'update for invalid moab', :update_version_after_validation
        end

        context 'incoming version same as catalog versions (both)' do
          it_behaves_like 'unexpected version with validation', :update_version_after_validation, 2, PreservedCopy::INVALID_MOAB_STATUS
        end

        context 'incoming version lower than catalog versions (both)' do
          it_behaves_like 'unexpected version with validation', :update_version_after_validation, 1, PreservedCopy::INVALID_MOAB_STATUS
        end

        context 'db update error' do
          let(:result_code) { AuditResults::DB_UPDATE_FAILED }

          context 'PreservedCopy ActiveRecordError' do
            let(:po) { build(:preserved_object) }
            let(:pc) { build(:preserved_copy) }
            let(:results) { po_handler.update_version_after_validation }

            before do
              allow(pc).to receive(:save!).and_raise(ActiveRecord::ActiveRecordError, 'foo')
              allow(PreservedObject).to receive(:find_by!).with(druid: druid).and_return(po)
              allow(PreservedCopy).to receive(:find_by!).with(preserved_object: po, endpoint: ep).and_return(pc)
              allow(Rails.logger).to receive(:log)
            end

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
          # PreservedObject won't get updated if moab is invalid
        end
      end
    end

    it_behaves_like 'druid not in catalog', :update_version_after_validation

    it_behaves_like 'PreservedCopy does not exist', :update_version_after_validation
  end
end
