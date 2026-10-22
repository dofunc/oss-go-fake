package oss

import (
	"encoding/hex"
	"encoding/xml"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/dofunc/oss-go-fake/internal/storage"
)

const (
	xmlTimeFormat = "2006-01-02T15:04:05.000Z"
	ownerID       = "oss-fake"
	storageClass  = "Standard"
	objectType    = "Normal"
)

type ownerXML struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

var owner = ownerXML{ID: ownerID, DisplayName: ownerID}

type bucketXML struct {
	Name             string `xml:"Name"`
	CreationDate     string `xml:"CreationDate"`
	Location         string `xml:"Location"`
	ExtranetEndpoint string `xml:"ExtranetEndpoint"`
	IntranetEndpoint string `xml:"IntranetEndpoint"`
	Region           string `xml:"Region"`
	StorageClass     string `xml:"StorageClass"`
}

type listAllMyBucketsResult struct {
	XMLName xml.Name    `xml:"ListAllMyBucketsResult"`
	Owner   ownerXML    `xml:"Owner"`
	Buckets []bucketXML `xml:"Buckets>Bucket"`
}

type bucketInfoXML struct {
	Name             string   `xml:"Name"`
	CreationDate     string   `xml:"CreationDate"`
	Location         string   `xml:"Location"`
	ExtranetEndpoint string   `xml:"ExtranetEndpoint"`
	IntranetEndpoint string   `xml:"IntranetEndpoint"`
	Region           string   `xml:"Region"`
	StorageClass     string   `xml:"StorageClass"`
	Owner            ownerXML `xml:"Owner"`
	Grant            string   `xml:"AccessControlList>Grant"`
}

type bucketInfoResult struct {
	XMLName xml.Name      `xml:"BucketInfo"`
	Bucket  bucketInfoXML `xml:"Bucket"`
}

type contentXML struct {
	Key          string    `xml:"Key"`
	LastModified string    `xml:"LastModified"`
	ETag         string    `xml:"ETag"`
	Type         string    `xml:"Type"`
	Size         int64     `xml:"Size"`
	StorageClass string    `xml:"StorageClass"`
	Owner        *ownerXML `xml:"Owner,omitempty"`
}

type commonPrefixXML struct {
	Prefix string `xml:"Prefix"`
}

type listBucketResultV1 struct {
	XMLName        xml.Name          `xml:"ListBucketResult"`
	Name           string            `xml:"Name"`
	Prefix         string            `xml:"Prefix"`
	Marker         string            `xml:"Marker"`
	MaxKeys        int               `xml:"MaxKeys"`
	Delimiter      string            `xml:"Delimiter"`
	EncodingType   string            `xml:"EncodingType,omitempty"`
	IsTruncated    bool              `xml:"IsTruncated"`
	NextMarker     string            `xml:"NextMarker,omitempty"`
	Contents       []contentXML      `xml:"Contents"`
	CommonPrefixes []commonPrefixXML `xml:"CommonPrefixes"`
}

type listBucketResultV2 struct {
	XMLName               xml.Name          `xml:"ListBucketResult"`
	Name                  string            `xml:"Name"`
	Prefix                string            `xml:"Prefix"`
	StartAfter            string            `xml:"StartAfter,omitempty"`
	ContinuationToken     string            `xml:"ContinuationToken,omitempty"`
	MaxKeys               int               `xml:"MaxKeys"`
	Delimiter             string            `xml:"Delimiter"`
	EncodingType          string            `xml:"EncodingType,omitempty"`
	IsTruncated           bool              `xml:"IsTruncated"`
	NextContinuationToken string            `xml:"NextContinuationToken,omitempty"`
	KeyCount              int               `xml:"KeyCount"`
	Contents              []contentXML      `xml:"Contents"`
	CommonPrefixes        []commonPrefixXML `xml:"CommonPrefixes"`
}

type deleteRequest struct {
	XMLName xml.Name `xml:"Delete"`
	Quiet   bool     `xml:"Quiet"`
	Objects []struct {
		Key string `xml:"Key"`
	} `xml:"Object"`
}

type deletedXML struct {
	Key string `xml:"Key"`
}

type deleteResult struct {
	XMLName      xml.Name     `xml:"DeleteResult"`
	EncodingType string       `xml:"EncodingType,omitempty"`
	Deleted      []deletedXML `xml:"Deleted"`
}

type copyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	LastModified string   `xml:"LastModified"`
	ETag         string   `xml:"ETag"`
}

func xmlTime(t time.Time) string {
	return t.UTC().Format(xmlTimeFormat)
}

// etag renders an object's ETag the way OSS does: upper-case hex MD5 in double quotes.
func etag(obj storage.Object) string {
	return `"` + strings.ToUpper(hex.EncodeToString(obj.MD5[:])) + `"`
}

func writeXML(w http.ResponseWriter, status int, v any) {
	body, err := xml.Marshal(v)
	if err != nil {
		slog.Error("encode response failed", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	writeBody(w, append([]byte(xml.Header), body...))
}
