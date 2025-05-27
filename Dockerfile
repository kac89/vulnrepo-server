FROM alpine:latest AS build

WORKDIR /vulnrepo-server
COPY . .

RUN apk add --no-cache git make musl-dev go

# Configure Go
ENV GOROOT=/usr/lib/go
ENV GOPATH=/go
ENV PATH=/go/bin:$PATH
RUN mkdir -p ${GOPATH}/src ${GOPATH}/bin

#Build vulnrepo-server
RUN go build vulnrepo-server.go

EXPOSE 443

# Run
CMD ["/vulnrepo-server/vulnrepo-server"]