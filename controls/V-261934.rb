control 'V-261934' do
  title 'When invalid inputs are received, PostgreSQL must behave in a predictable and documented manner that reflects organizational and system objectives.'
  desc 'check', <<~EOT
    Review system documentation to determine how input errors from application to PostgreSQL are to be handled in general and if any special handling is defined for specific circumstances.

    If it does not implement the documented behavior, this is a finding.

    As the database administrator (shown here as "postgres"), make a small SQL syntax error in psql by running the following:

    $ sudo su - postgres
    $ psql -c "CREAT TABLE incorrect_syntax(id INT)"
    ERROR: syntax error at or near "CREAT"

    Note: The following instructions use the PGVER and PGLOG environment variables. Refer to supplementary content APPENDIX-H for instructions on configuring PGVER and APPENDIX-I for PGLOG.

    As the database administrator (shown here as "postgres"), verify the syntax error was logged (change the log file name and part to suit the circumstances):

    $ sudo su - postgres
    $ cat ~/${PGVER?}/data/${PGLOG?}/<latest log>
    2024-03-30 16:18:10.772 EDT postgres postgres 5706bb87.90dERROR: syntax error at or near "CREAT" at character 1
    2024-03-30 16:18:10.772 EDT postgres postgres 5706bb87.90dSTATEMENT: CREAT TABLE incorrect_syntax(id INT);

    If no matching log entry containing the 'ERROR: syntax error' is present, this is a finding.
  EOT
  desc 'fix', <<~EOT
    Enable logging.

    To ensure logging is enabled, see the instructions in the supplementary content APPENDIX-C.

    All errors and denials are logged if logging is enabled.
  EOT
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag gid: 'V-261934'
  tag rid: 'SV-261934r1000807_rule'
  tag stig_id: 'CD16-00-009000'
  tag cci: ["CCI-002754"]
  tag nist: []
  describe 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.' do
    skip 'This control requires manual review: it depends on organization-defined policy, documented procedures, and/or artifacts (e.g., system security plan, PPSM CAL, access control documentation, AWS Console/CloudWatch configuration) that cannot be verified via an automated SQL session or the AWS CLI alone.'
  end
end
