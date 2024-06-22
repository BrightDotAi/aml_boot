FROM  --platform=$BUILDPLATFORM brightai/cross-rust-musl:latest AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG GITHUB_USERNAME
ARG GITHUB_PAT

WORKDIR /aml_boot
COPY . .

# cargo build
RUN . /setup_env.sh && \
    cargo build --release --target=$TARGET && \
    cp /aml_boot/target/$TARGET/release/aml_boot /aml_boot/target/release/aml_boot && \
    $strip_app /aml_boot/target/release/aml_boot

FROM alpine:3.19 AS runner
WORKDIR /aml_boot
COPY --from=builder /aml_boot/target/release/aml_boot /aml_boot/aml_boot
ENV PATH="/aml_boot:$PATH"
