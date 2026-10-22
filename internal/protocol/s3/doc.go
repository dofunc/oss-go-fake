// Package s3 reserves the place of the Amazon S3 protocol. This release only recognises S3
// requests by their signature markers and answers them with 501 NotImplemented; the protocol
// itself is not implemented. A future implementation translates S3 requests into calls on the
// same service layer the OSS protocol uses.
package s3
