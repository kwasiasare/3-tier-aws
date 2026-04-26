@description('Container App principal ID')
param containerAppPrincipalId string

@description('Cosmos DB account resource ID')
param cosmosDbAccountId string

@description('Storage account resource ID')
param storageAccountId string

@description('Key Vault resource ID')
param keyVaultId string

// Cosmos DB Built-in Data Contributor Role
resource cosmosDbDataContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(cosmosDbAccountId, containerAppPrincipalId, 'b24988ac-6180-42a0-ab88-20f7382dd24c')
  scope: cosmosDbAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')
    principalId: containerAppPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Storage Blob Data Contributor Role
resource storageBlobDataContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccountId, containerAppPrincipalId, 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: containerAppPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Key Vault Secrets User Role
resource keyVaultSecretsUserRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVaultId, containerAppPrincipalId, '4633458b-17de-408a-b874-0445c86b69e6')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: containerAppPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource cosmosDbAccount 'Microsoft.DocumentDB/databaseAccounts@2024-05-15' existing = {
  name: last(split(cosmosDbAccountId, '/'))
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' existing = {
  name: last(split(storageAccountId, '/'))
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: last(split(keyVaultId, '/'))
}