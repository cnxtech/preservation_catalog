require 'rails_helper'

describe S3EndpointDeliveryJob, type: :job do
  let(:druid) { 'bj102hs9687' }
  let(:version) { 1 }
  let(:dvz) { DruidVersionZip.new(druid, version) }
  let(:object) { instance_double(Aws::S3::Object, exists?: false, put: true) }
  let(:bucket) { instance_double(Aws::S3::Bucket, object: object) }

  before do
    allow(Settings).to receive(:zip_storage).and_return(Rails.root.join('spec', 'fixtures', 'zip_storage'))
    allow(PreservationCatalog::S3).to receive(:bucket).and_return(bucket)
  end

  it 'descends from EndpointDeliveryBase' do
    expect(described_class.new).to be_an(EndpointDeliveryBase)
  end

  it 'populates a DruidVersionZip' do
    expect(DruidVersionZip).to receive(:new).with(druid, version).and_return(dvz)
    described_class.perform_now(druid, version)
  end

  context 'zip already exists on s3' do
    before { allow(object).to receive(:exists?).and_return(true) }

    it 'does nothing' do
      expect(object).not_to receive(:put)
      described_class.perform_now(druid, version)
    end
  end

  context 'zip is new to S3' do
    it 'puts to S3' do
      expect(object).to receive(:put).with(
        a_hash_including(body: File, metadata: a_hash_including(checksum_md5: 'd41d8cd98f00b204e9800998ecf8427e'))
      )
      described_class.perform_now(druid, version)
    end
  end

  it 'invokes ResultsRecorderJob' do
    expect(ResultsRecorderJob).to receive(:perform_later).with(druid, version, 's3', '12345ABC')
    described_class.perform_now(druid, version)
  end
end
