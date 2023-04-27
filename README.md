# XRPL ZKBRIDGE
## About The Project

This project's goal is to test the following:

* How could the light client verification be implemented if mimc and bn254 where used instead of sha512 and Curve25519 since none of those are yet implemented
* Test if decentralized zkp generation using Virgo would be needed or if it could be done in a centralized way and save infrastructure. 
* Check if the XChainCommit transaction was in the development server to be able to test the zkbridge

### Results

* ZKP generation can be done in a centralized way, since for the test cases it takes around 4 seconds to generate the proof. The circuit specific setup phase is what takes the longest and only takes 30s, which is not a problem since it can be done one time and stored in a file.
* The XChainCommit transaction is was not yet enabled in the development server, so it is not possible to test the zkbridge. Nonetheless I still kept the code in the repo since it might be useful once they enable the proposed [XLS-38](https://github.com/XRPLF/XRPL-Standards/discussions/92) extension.

## How to run the project

### For the light client verification

Install all dependencies

```go get -d .```

And then test the circuit

```go test```

### For the lock tokens xrp

Install xrpl with npm

```npm install xrpl```

Open the html document and choose Testnet, click Get New Standby Account and Get New Operational Account.

Set the corresponding amounts and click Lock Tokens. It now say that the transaction does not exist, this is because it's not yet enabled.