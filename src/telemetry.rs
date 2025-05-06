use opentelemetry::trace::TracerProvider;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::SpanExporter;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::resource::Resource;
use opentelemetry_sdk::trace::{self, RandomIdGenerator, Sampler};
use opentelemetry_semantic_conventions::resource::{
    SERVICE_NAME, SERVICE_VERSION, TELEMETRY_SDK_LANGUAGE, TELEMETRY_SDK_NAME,
    TELEMETRY_SDK_VERSION,
};
use tracing_log::LogTracer;
use tracing_opentelemetry::{OpenTelemetryLayer,};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, registry, EnvFilter};

pub fn init_telemetry(
    service_name: &str,
    service_version: &str,
    otlp_endpoint: Option<String>,
) -> Result<Option<trace::SdkTracerProvider>, Box<dyn std::error::Error>> {
    let _ = LogTracer::init();

    let Some(endpoint) = otlp_endpoint else {
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"));

        let subscriber = registry()
            .with(env_filter)
            .with(fmt::layer());

        match tracing_subscriber::util::SubscriberInitExt::try_init(subscriber) {
            Ok(_) => {},
            Err(e) => eprintln!("Warning: Could not initialize subscriber: {}", e),
        }

        return Ok(None);
    };

    let resource = Resource::builder()
        .with_attribute(KeyValue::new(SERVICE_NAME, service_name.to_string()))
        .with_attribute(KeyValue::new(SERVICE_VERSION, service_version.to_string()))
        .with_attribute(KeyValue::new(TELEMETRY_SDK_NAME, "opentelemetry".to_string()))
        .with_attribute(KeyValue::new(TELEMETRY_SDK_VERSION, env!("CARGO_PKG_VERSION").to_string()))
        .with_attribute(KeyValue::new(TELEMETRY_SDK_LANGUAGE, "rust".to_string()))
        .build();

    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    let processor = trace::BatchSpanProcessor::new(exporter, trace::BatchConfig::default());

    let provider = trace::SdkTracerProvider::builder()
        .with_resource(resource)
        .with_sampler(Sampler::AlwaysOn)
        .with_span_processor(processor)
        .with_id_generator(RandomIdGenerator::default())
        .build();

    global::set_tracer_provider(provider.clone());
    global::set_text_map_propagator(TraceContextPropagator::new());

    let tracer = provider.tracer("paas-server");
    let otel_layer = OpenTelemetryLayer::new(tracer);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = registry()
        .with(env_filter)
        .with(fmt::layer())
        .with(otel_layer);

    match tracing_subscriber::util::SubscriberInitExt::try_init(subscriber) {
        Ok(_) => {},
        Err(e) => eprintln!("Warning: Could not initialize subscriber with OpenTelemetry: {}", e),
    }

    Ok(Some(provider))
}

/// Ensure OpenTelemetry pipeline is flushed and shut down on app exit
pub fn shutdown_tracer_provider(
    tracer_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
) {
    if let Some(provider) = tracer_provider {
        // Force export all pending spans
        let _ = provider.force_flush();
        let _ = provider.shutdown();
    }
}
