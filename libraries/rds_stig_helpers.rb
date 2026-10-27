# Control-body helpers shared across this profile's controls.
#
# InSpec evaluates each control block on an Inspec::Rule instance, so these are
# mixed into Inspec::Rule; inside them `input`, `describe`, `only_if`, and
# resources behave exactly as they would written inline in a control.
module RdsStigHelpers
  # The profile's aws_rds_connection, built from the standard connection inputs.
  def rds_connection
    aws_rds_connection(
      aws_instance_id: input('aws_db_instance_identifier'),
      region: input('aws_region'),
      profile: input('aws_cli_profile'),
      host: input('pg_host'),
      port: input('pg_port'),
      db: input('pg_db'),
      dba: input('pg_dba')
    )
  end

  # Skips the calling control unless AWS CLI discovery is in use. Once it is, AWS
  # call failures fail the control (see aws_rds_connection) rather than skip it.
  def rds_only_if_aws(conn)
    only_if('The AWS CLI must be installed and the aws_db_instance_identifier input set to evaluate this control.') do
      conn.aws_available?
    end
  end

  # Flags parameter-group changes not yet applied to the running instance, so a
  # live SHOW value is never mistaken for the configured one. No-op without AWS.
  def rds_check_parameter_apply_status(conn)
    return unless conn.aws_available?
    describe 'RDS DB parameter group apply status (flags parameter-group changes not yet applied to the running instance)' do
      subject { conn.parameter_apply_status }
      it { should_not cmp 'pending-reboot' }
    end
  end

  # PPSM exposure check on each of the instance's VPC security groups (V-261889,
  # V-261926), given conn.security_group_ingress: no 0.0.0.0/0 ingress, and only
  # CIDRs listed in pg_approved_ingress_cidrs. Callers must also assert the group
  # list is non-empty, in a describe written in the control itself (`inspec
  # check` only counts describe blocks it can see in the control's source).
  def rds_check_security_group_ingress(groups)
    approved_cidrs = input('pg_approved_ingress_cidrs')

    groups.each do |group|
      cidrs = group[:cidrs]
      describe "Security group #{group[:id]} ingress CIDRs (#{cidrs.join(', ')})" do
        it 'should not include the public 0.0.0.0/0 range' do
          expect(cidrs).not_to include('0.0.0.0/0')
        end
        it 'should only include CIDRs approved via the pg_approved_ingress_cidrs input (PPSM CAL / vulnerability assessment)' do
          expect(cidrs - approved_cidrs).to be_empty
        end
      end
    end
  end
end

::Inspec::Rule.include(RdsStigHelpers)
