This is the implementation of the project of "Data and Network Security" course at Sharif University of Technology.

It consists of authentication, authorization, and delegation protocols based on x.509 certificates (and no passwords) above a TLS layer.
The CA is responsible for issuing certificates for nodes in the network. Any node is supposed to obtain its certificate from CA on startup.

The scenario that this project is designed for is a payment gateway using the bank for regular online shopping.
Also, the delegation of currency exchange to a third-party agency from the user to the bank is possible in the case that there is not enough credit in the account, 
so the bank can exchange cryptocurrencies to proceed with the payment.

Additionally, the protocol comprosises of verification in different stages.

All nodes are written using flask web framework to have a concise and clear interface.
The cryptographic actions, such as asymmetric encryption, digital signatures, and certifcates, are done using [`cryptography`](https://pypi.org/project/cryptography/) library.
