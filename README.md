# Network-Communication-and-Security
## Protocol Requirements
The following protocol features are required:
(1) Anauthenticationmechanismmustbeincluded.ClientandServerrequiremutual authentication.
(2) Allmessagesshouldbeprotectedagainstmodificationandtheymustbeauthenticated.For this purpose, a MAC must be computed and included in messages.
(3) AlldatainDATA_RESPONSEmessagesmustbetransmittedconfidentially.Forthis purpose, encryption must be used.
For message encryption and MAC individual session keys must be negotiated. The encryption key should be refreshed every
10 DATA_RESPONSE messages. To facilitate authentication and key negotiation it might be necessary to extend existing messages and it might be necessary to define new message types.