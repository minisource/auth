export async function register() {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    const otelEnabled = process.env.OTEL_ENABLED === 'true' || process.env.TRACING_ENABLED === 'true';
    if (!otelEnabled) return;

    try {
      const { NodeSDK } = await import('@opentelemetry/sdk-node');
      const { OTLPTraceExporter } = await import('@opentelemetry/exporter-trace-otlp-http');
      
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const resourcesImport = await import('@opentelemetry/resources') as any;
      
      // Handle both ES module and CommonJS import wrappers safely
      const ResourceClass = resourcesImport.Resource || resourcesImport.default?.Resource;
      if (!ResourceClass) {
        throw new Error('Resource class not found in @opentelemetry/resources');
      }

      let endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318';
      // Ensure HTTP OTLP path is suffix-correct
      if (!endpoint.endsWith('/v1/traces')) {
        endpoint = endpoint.replace(/\/$/, '') + '/v1/traces';
      }

      const sdk = new NodeSDK({
        resource: new ResourceClass({
          'service.name': process.env.OTEL_SERVICE_NAME || 'auth-frontend',
          'deployment.environment': process.env.NODE_ENV || 'development',
        }),
        traceExporter: new OTLPTraceExporter({
          url: endpoint,
        }),
      });

      sdk.start();
    } catch (err) {
      console.warn('Failed to initialize OpenTelemetry on Server-side:', err);
    }
  }
}
