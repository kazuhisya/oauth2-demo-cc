# vi: set ft=dockerfile :

FROM golang:alpine AS build-env
WORKDIR /root
RUN apk update && \
        apk add git && \
        rm -rf /var/cache/apk/*
RUN go get -u gopkg.in/oauth2.v3 github.com/dgrijalva/jwt-go github.com/tidwall/buntdb
ADD server.go /root/server.go
RUN go build server.go



FROM alpine:3.9
MAINTAINER Kazuhisa Hara <khara@sios.com>
WORKDIR /root
COPY --from=build-env /root/server /root/server
ADD client.json /root/client.json
EXPOSE 9096
CMD /root/server
