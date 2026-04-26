@description('Deployment location')
param location string

@description('Project name for resource naming')
param projectName string

@description('Environment type')
param environment string

@description('Public subnet resource ID')
param publicSubnetId string

@description('Container App FQDN')
param containerAppFqdn string

// Public IP Address
resource publicIp 'Microsoft.Network/publicIPAddresses@2024-01-01' = {
  name: '${projectName}-${toLower(environment)}-appgw-pip-${uniqueString(resourceGroup().id, 'pip')}'
  location: location
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
    dnsSettings: {
      domainNameLabel: '${toLower(projectName)}-${toLower(environment)}-appgw-${uniqueString(resourceGroup().id, 'pip')}'
    }
  }
  tags: {
    environment: environment
    project: projectName
    managedBy: 'bicep'
  }
}

// Application Gateway
resource applicationGateway 'Microsoft.Network/applicationGateways@2024-01-01' = {
  name: '${projectName}-${toLower(environment)}-appgw-${uniqueString(resourceGroup().id, 'appgw')}'
  location: location
  properties: {
    sku: {
      name: 'Standard_v2'
      tier: 'Standard_v2'
      capacity: 1
    }
    gatewayIPConfigurations: [
      {
        name: 'appGatewayIpConfig'
        properties: {
          subnet: {
            id: publicSubnetId
          }
        }
      }
    ]
    frontendIPConfigurations: [
      {
        name: 'appGwPublicFrontendIp'
        properties: {
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
    frontendPorts: [
      {
        name: 'port_80'
        properties: {
          port: 80
        }
      }
      {
        name: 'port_443'
        properties: {
          port: 443
        }
      }
    ]
    backendAddressPools: [
      {
        name: 'containerAppBackendPool'
        properties: {
          backendAddresses: [
            {
              fqdn: containerAppFqdn
            }
          ]
        }
      }
    ]
    backendHttpSettingsCollection: [
      {
        name: 'appGatewayBackendHttpSettings'
        properties: {
          port: 443
          protocol: 'Https'
          cookieBasedAffinity: 'Disabled'
          pickHostNameFromBackendAddress: true
          requestTimeout: 30
        }
      }
    ]
    httpListeners: [
      {
        name: 'appGatewayHttpListener'
        properties: {
          frontendIPConfiguration: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendIPConfigurations', '${projectName}-${toLower(environment)}-appgw-${uniqueString(resourceGroup().id, 'appgw')}', 'appGwPublicFrontendIp')
          }
          frontendPort: {
            id: resourceId('Microsoft.Network/applicationGateways/frontendPorts', '${projectName}-${toLower(environment)}-appgw-${uniqueString(resourceGroup().id, 'appgw')}', 'port_80')
          }
          protocol: 'Http'
        }
      }
    ]
    requestRoutingRules: [
      {
        name: 'rule1'
        properties: {
          ruleType: 'Basic'
          priority: 100
          httpListener: {
            id: resourceId('Microsoft.Network/applicationGateways/httpListeners', '${projectName}-${toLower(environment)}-appgw-${uniqueString(resourceGroup().id, 'appgw')}', 'appGatewayHttpListener')
          }
          backendAddressPool: {
            id: resourceId('Microsoft.Network/applicationGateways/backendAddressPools', '${projectName}-${toLower(environment)}-appgw-${uniqueString(resourceGroup().id, 'appgw')}', 'containerAppBackendPool')
          }
          backendHttpSettings: {
            id: resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', '${projectName}-${toLower(environment)}-appgw-${uniqueString(resourceGroup().id, 'appgw')}', 'appGatewayBackendHttpSettings')
          }
        }
      }
    ]
    enableHttp2: true
    autoscaleConfiguration: {
      minCapacity: 1
      maxCapacity: 3
    }
  }
  tags: {
    environment: environment
    project: projectName
    managedBy: 'bicep'
  }
}

output applicationGatewayId string = applicationGateway.id
output applicationGatewayPublicIp string = publicIp.properties.ipAddress
output applicationGatewayFqdn string = publicIp.properties.dnsSettings.fqdn