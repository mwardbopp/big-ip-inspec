# copyright: 2018, The Authors

title "Verify BIG-IP availability"

BIGIP_HOST     = input('bigip_address')
BIGIP_PORT     = input('bigip_port')
BIGIP_USER     = input('user')
BIGIP_PASSWORD = input('password')
DO_VERSION     = input('do_version')
AS3_VERSION    = input('as3_version')
TS_VERSION     = input('ts_version')
FAST_VERSION   = input('fast_version')

control "bigip-connectivity" do
  impact 1.0
  title "BIG-IP is reachable"
  describe host(BIGIP_HOST, port: BIGIP_PORT, protocol: 'tcp') do
      it { should be_reachable }
  end
end 

control "cis-f5-benchmark-1.1.3" do                                                                     
    impact 1.0                                                                                        
    title "Configure Secure Password Policy (Manual)"                                                   
    describe json(content: http("https://#{BIGIP_HOST}:#{BIGIP_PORT}/mgmt/tm/auth/password-policy",
              auth: {user: BIGIP_USER, pass: BIGIP_PASSWORD},
              method: 'GET',
              ssl_verify: false).body) do
          its('policyEnforcement') { should eq 'enabled' }
          its('minimumLength') { should eq 14 }
          its('requiredSpecial') { should eq 3 }
          its('requiredUppercase') { should eq 3 }
          its('requiredLowercase') { should eq 3 }
          its('requiredNumeric') { should eq 3 }
          its('minDuration') { should eq 0 }
          its('maxDuration') { should eq 99999 }
          its('passwordMemory') { should eq 5 }
          its('maxLoginFailures') { should eq 3 }
    end
  end