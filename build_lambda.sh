#create golang binary
echo "started buidling golang binary..."

GOARCH=arm64 GOOS=linux go build -tags lambda.norpc -o ./bin/bootstrap
echo "successfully created go binary..."

#zip lambda
cd bin/

echo "zipping go binary"
zip ../manage_sg.zip bootstrap