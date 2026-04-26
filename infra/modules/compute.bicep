@description('Deployment location')
param location string

@description('Project name for resource naming')
param projectName string

@description('Environment type')
param environment string

@description('Private subnet resource ID')
param privateSubnetId string

@description('Log Analytics Workspace resource ID')
param logAnalyticsWorkspaceId string

@description('Application Insights connection string')
@secure()
param applicationInsightsConnectionString string

@description('Minimum number of replicas')
param minReplicas int

@description('Maximum number of replicas')
param maxReplicas int

@description('Container image')
param containerImage string

@description('Cosmos DB endpoint')
param cosmosDbEndpoint string

@description('Storage account name')
param storageAccountName string

@description('Key Vault URI')
param keyVaultUri string

// Container Apps Environment
resource containerAppsEnvironment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${projectName}-${toLower(environment)}-cae-${uniqueString(resourceGroup().id)}'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: reference(logAnalyticsWorkspaceId, '2023-09-01').customerId
        sharedKey: listKeys(logAnalyticsWorkspaceId, '2023-09-01').primarySharedKey
      }
    }
    vnetConfiguration: {
      infrastructureSubnetId: privateSubnetId
      internal: true
    }
    zoneRedundant: false
  }
  tags: {
    environment: environment
    project: projectName
    managedBy: 'bicep'
  }
}

// Container App
resource containerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${projectName}-${toLower(environment)}-app-${uniqueString(resourceGroup().id)}'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    environmentId: containerAppsEnvironment.id
    configuration: {
      ingress: {
        external: false
        targetPort: 80
        allowInsecure: false
        traffic: [
          {
            weight: 100
            latestRevision: true
          }
        ]
      }
      secrets: [
        {
          name: 'app-insights-connection-string'
          value: applicationInsightsConnectionString
        }
      ]
      registries: []
    }
    template: {
      containers: [
        {
          name: 'main'
          image: containerImage
          env: [
            {
              name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
              secretRef: 'app-insights-connection-string'
            }
            {
              name: 'COSMOS_DB_ENDPOINT'
              value: cosmosDbEndpoint
            }
            {
              name: 'STORAGE_ACCOUNT_NAME'
              value: storageAccountName
            }
            {
              name: 'KEY_VAULT_URI'
              value: keyVaultUri
            }
            {
              name: 'ENVIRONMENT'
              value: environment
            }
          ]
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
        rules: [
          {
            name: 'http-scaling'
            http: {
              metadata: {
                concurrentRequests: '100'
              }
            }
          }
        ]
      }
    }
  }
  tags: {
    environment: environment
    project: projectName
    managedBy: 'bicep'
  }
}

output containerAppPrincipalId string = containerApp.identity.principalId
output containerAppFqdn string = containerApp.properties.configuration.ingress.fqdn
output containerAppId string = containerApp.id