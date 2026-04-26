@description('Deployment location')
param location string

@description('Project name for resource naming')
param projectName string

@description('Environment type')
param environment string

@description('Database subnet resource ID')
param databaseSubnetId string

@description('Key Vault resource ID')
param keyVaultId string

// Cosmos DB Account
resource cosmosAccount 'Microsoft.DocumentDB/databaseAccounts@2024-05-15' = {
  name: '${projectName}-${toLower(environment)}-cosmos-${uniqueString(resourceGroup().id)}'
  location: location
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    consistencyPolicy: {
      defaultConsistencyLevel: 'Session'
    }
    locations: [
      {
        locationName: location
        failoverPriority: 0
        isZoneRedundant: false
      }
    ]
    capabilities: [
      {
        name: 'EnableServerless'
      }
    ]
    publicNetworkAccess: 'Disabled'
    disableKeyBasedMetadataWriteAccess: false
    enableFreeTier: false
    capacity: {
      totalThroughputLimit: 1000
    }
  }
  tags: {
    environment: environment
    project: projectName
    managedBy: 'bicep'
  }
}

// Cosmos DB Database
resource cosmosDatabase 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2024-05-15' = {
  parent: cosmosAccount
  name: 'EmployeeDB'
  properties: {
    resource: {
      id: 'EmployeeDB'
    }
  }
}

// Cosmos DB Container for Employee Records
resource cosmosContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2024-05-15' = {
  parent: cosmosDatabase
  name: 'Employees'
  properties: {
    resource: {
      id: 'Employees'
      partitionKey: {
        paths: [
          '/employeeId'
        ]
        kind: 'Hash'
      }
      indexingPolicy: {
        indexingMode: 'consistent'
        automatic: true
        includedPaths: [
          {
            path: '/*'
          }
        ]
        excludedPaths: [
          {
            path: '/"_etag"/?'
          }
        ]
      }
    }
  }
}

// Private Endpoint for Cosmos DB
resource cosmosPrivateEndpoint 'Microsoft.Network/privateEndpoints@2024-01-01' = {
  name: '${cosmosAccount.name}-pe'
  location: location
  properties: {
    subnet: {
      id: databaseSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${cosmosAccount.name}-pe-connection'
        properties: {
          privateLinkServiceId: cosmosAccount.id
          groupIds: [
            'Sql'
          ]
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

// Private DNS Zone Group for Cosmos DB Private Endpoint
resource cosmosPrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-01-01' = {
  parent: cosmosPrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'privatelink-documents-azure-com'
        properties: {
          privateDnsZoneId: resourceId('Microsoft.Network/privateDnsZones', 'privatelink.documents.azure.com')
        }
      }
    ]
  }
}

// Store Cosmos DB Connection String in Key Vault
resource cosmosConnectionStringSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'cosmos-connection-string'
  properties: {
    value: cosmosAccount.listConnectionStrings().connectionStrings[0].connectionString
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: last(split(keyVaultId, '/'))
}

output cosmosDbAccountId string = cosmosAccount.id
output cosmosDbEndpoint string = cosmosAccount.properties.documentEndpoint
output cosmosDatabaseName string = cosmosDatabase.name
output cosmosContainerName string = cosmosContainer.name