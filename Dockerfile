FROM alpine:latest AS build

RUN apk add git
RUN git clone https://github.com/kac89/vulnrepo-server.git
WORKDIR /vulnrepo-server

RUN apk add --no-cache git make musl-dev go

# Configure Go
ENV GOROOT=/usr/lib/go
ENV GOPATH=/go
ENV PATH=/go/bin:$PATH
RUN mkdir -p ${GOPATH}/src ${GOPATH}/bin

#Build vulnrepo-server
RUN go build vulnrepo-server.go

#EXPOSE 8080

#RUN echo $(ls -la)

# Run
CMD ["/vulnrepo-server/vulnrepo-server"]