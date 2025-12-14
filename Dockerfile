FROM alpine:latest as builder

# Install packages
RUN apk add --update --no-cache unzip openjdk8 libpcap-dev

# Copy files
COPY . /CICFlowMeter/

# Set working directory
WORKDIR /CICFlowMeter

# Build from sources
RUN ./gradlew distZip

# Unpack the binary
RUN UNZIP_DISABLE_ZIPBOMB_DETECTION=TRUE unzip -o build/distributions/CICFlowMeter-*.zip -d build/distributions

FROM alpine:latest

# Install packages
RUN apk add --update --no-cache openjdk8 libpcap-dev

# Set working directory
WORKDIR /CICFlowMeter

# Copy files from build
COPY --from=builder /CICFlowMeter/build/distributions/CICFlowMeter-* .

# Set working directory - important since relative path is used in the cli "-Djava.library.path=../lib/native"
WORKDIR /CICFlowMeter/bin

# RUN CICFlowMeter cli to extract features from a live interface
# USAGE: docker run --net=host --privileged -v /path/to/output:/tmp/captures cicflowmeter
ENTRYPOINT ["./cfm", "-live", "/tmp/captures"]
