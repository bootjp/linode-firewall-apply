FROM golang:latest AS build
WORKDIR $GOPATH/src/bootjp/linode-firewall-apply
COPY . .
RUN go build main.go
RUN cp main /app

FROM gcr.io/distroless/static:latest
COPY --from=build /app /app

CMD ["/app"]