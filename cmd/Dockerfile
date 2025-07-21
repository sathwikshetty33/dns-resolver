FROM golang:tip-alpine3.22

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o app ./cmd

EXPOSE 8001

CMD ["./app"]
