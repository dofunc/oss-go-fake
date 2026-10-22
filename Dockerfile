FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/oss-go-fake /usr/bin/oss-go-fake
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/bin/oss-go-fake"]
CMD ["serve", "--data-dir", "/data"]
