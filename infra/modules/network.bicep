@description('Deployment location')
param location string

@description('Project name for resource naming')
param projectName string

@description('Environment type')
param environment string

@description('Virtual network CIDR block')
param vnetCidr string

@description('Public subnet CIDR block')
param publicSubnetCidr string

@description('Private subnet CIDR block')
param privateSubnetCidr string

@description('Database subnet CIDR block')
param databaseSubnetCidr string

// Network Security Group for Application Gateway
resource appGatewayNsg 'Microsoft.Network/networkSecurityGroups@2024-01-01' = {
  name: '${projectName}-${toLower(environment)}-appgw-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowHTTPS'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowHTTP'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '80'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 110
          direction: 'Inbound'
        }
      }
      {
        name: 'AllowGatewayManager'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '65200-65535'
          sourceAddressPrefix: 'GatewayManager'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 120
          direction: 'Inbound'
        }
      }
    ]
  }
  tags: {
    environment: environment
    project: projectName
    managedBy: 'bicep'
  }
}

// Network Security Group for Container Apps
resource containerAppNsg 'Microsoft.Network/networkSecurityGroups@2024-01-01' = {
  name: '${projectName}-${toLower(environment)}-container-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowAppGateway'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: publicSubnetCidr
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
    ]
  }
  tags: {
    environment: environment
    project: projectName
    managedBy: 'bicep'
  }
}

// Network Security Group for Database Subnet
resource databaseNsg 'Microsoft.Network/networkSecurityGroups@2024-01-01' = {
  name: '${projectName}-${toLower(environment)}-db-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowContainerApps'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: privateSubnetCidr
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
    ]
  }
  tags: {
    environment: environment
    project: projectName
    managedBy: 'bicep'
  }
}

// Virtual Network
resource vnet 'Microsoft.Network/virtualNetworks@2024-01-01' = {
  name: '${projectName}-${toLower(environment)}-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        vnetCidr
      ]
    }
    subnets: [
      {
        name: 'public-subnet'
        properties: {
          addressPrefix: publicSubnetCidr
          networkSecurityGroup: {
            id: appGatewayNsg.id
          }
        }
      }
      {
        name: 'private-subnet'
        properties: {
          addressPrefix: privateSubnetCidr
          networkSecurityGroup: {
            id: containerAppNsg.id
          }
          delegations: [
            {
              name: 'Microsoft.App.environments'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: 'database-subnet'
        properties: {
          addressPrefix: databaseSubnetCidr
          networkSecurityGroup: {
            id: databaseNsg.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
  tags: {
    environment: environment
    project: projectName
    managedBy: 'bicep'
  }
}

// Private DNS Zone for Cosmos DB
resource cosmosPrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.documents.azure.com'
  location: 'global'
  tags: {
    environment: environment
    project: projectName
    managedBy: 'bicep'
  }
}

// Private DNS Zone VNet Link for Cosmos DB
resource cosmosPrivateDnsZoneVnetLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: cosmosPrivateDnsZone
  name: '${projectName}-cosmos-vnet-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

// Private DNS Zone for Storage
resource storagePrivateDnsZone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.blob.core.windows.net'
  location: 'global'
  tags: {
    environment: environment
    project: projectName
    managedBy: 'bicep'
  }
}

// Private DNS Zone VNet Link for Storage
resource storagePrivateDnsZoneVnetLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: storagePrivateDnsZone
  name: '${projectName}-storage-vnet-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}

output vnetId string = vnet.id
output publicSubnetId string = vnet.properties.subnets[0].id
output privateSubnetId string = vnet.properties.subnets[1].id
output databaseSubnetId string = vnet.properties.subnets[2].id
output cosmosPrivateDnsZoneId string = cosmosPrivateDnsZone.id
output storagePrivateDnsZoneId string = storagePrivateDnsZone.id