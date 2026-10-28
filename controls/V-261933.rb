control 'V-261933' do
  title 'PostgreSQL must maintain the confidentiality and integrity of information during reception.'
  desc <<~EOT
    Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

    This requirement applies only to those applications that are either distributed or can allow access to data nonlocally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

    When receiving data, PostgreSQL, associated applications, and infrastructure must leverage protection mechanisms.
  EOT
  desc 'check', <<~EOT
    If the data owner does not have a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process, this is not a finding.

    As the database administrator (shown here as "postgres"), verify SSL is enabled in postgresql.conf by running the following SQL:

    $ sudo su - postgres
    $ psql -c "SHOW ssl" 

    If SSL is off, this is a finding.

    If PostgreSQL, associated applications, and infrastructure do not employ protective measures against unauthorized disclosure and modification during reception, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Implement protective measures against unauthorized disclosure and modification during reception.

    To configure PostgreSQL to use SSL, refer to supplementary content APPENDIX-G for instructions on enabling SSL.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000442-DB-000379'
  tag gid: 'V-261933'
  tag rid: 'SV-261933r1000804_rule'
  tag stig_id: 'CD16-00-008900'
  tag cci: ["CCI-002422"]
  tag nist: ["SC-8 (2)"]
  conn = rds_connection
  sql = conn.sql_session(input('pg_dba_password'))

  describe sql.query('SHOW ssl;', [conn.db]) do
    its('output.strip') { should cmp input('pg_ssl') }
  end

  rds_check_parameter_apply_status(conn)
end
