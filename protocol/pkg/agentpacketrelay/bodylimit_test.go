package agentpacketrelay

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// oversizedAck sends an acknowledgement whose chunked body runs past its
// 32-byte bound and reports the status, whether the answer announced
// Connection: close, and whether the server then closed the connection.
func oversizedAck(t *testing.T, opts ...relayOption) (int, bool, bool) {
	t.Helper()
	relay := newTestRelay(t, testLimits(), opts...)
	alice := newRecipient(t)
	env := alice.seal(t, testPacket(8), relay.clock.unix()+600)
	expectStatus(t, relay.putSealed(env), 201)
	conn, err := net.Dial("tcp", strings.TrimPrefix(relay.http.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	body := string(env.secret[:]) + strings.Repeat("x", 200)
	path := strings.TrimPrefix(relay.envelopeURL(alice.agentID, env.id), relay.http.URL) + "/ack"
	request := "POST " + path + " HTTP/1.1\r\nHost: relay\r\nContent-Type: " + ContentTypeEnvelope +
		"\r\nTransfer-Encoding: chunked\r\n\r\n" + strconv.FormatInt(int64(len(body)), 16) + "\r\n" + body + "\r\n0\r\n\r\n"
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	answer, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, answer.Body)
	answer.Body.Close()
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err = reader.ReadByte()
	closed := errors.Is(err, io.EOF)
	if !closed && !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("reading after the answer: %v", err)
	}
	return answer.StatusCode, answer.Close, closed
}

// TestCountingKeepsConnectionHandling: with counting on, an oversized body
// is answered and its connection handled exactly as with counting off.
func TestCountingKeepsConnectionHandling(t *testing.T) {
	status, announced, closed := oversizedAck(t)
	if status != http.StatusBadRequest {
		t.Fatalf("oversized chunked ack = %d", status)
	}
	countedStatus, countedAnnounced, countedClosed := oversizedAck(t, withMetrics(NewMetrics()))
	if countedStatus != status || countedAnnounced != announced || countedClosed != closed {
		t.Fatalf("with counting: %d close=%v closed=%v; without: %d close=%v closed=%v",
			countedStatus, countedAnnounced, countedClosed, status, announced, closed)
	}
}

// TestConnWriterUnwraps: the body bound is always handed the server's own
// writer, never the counting wrapper.
func TestConnWriterUnwraps(t *testing.T) {
	inner := httptest.NewRecorder()
	if got := connWriter(&statusWriter{ResponseWriter: inner}); got != inner {
		t.Fatal("connWriter returned the counting wrapper")
	}
	if got := connWriter(inner); got != inner {
		t.Fatal("connWriter changed an unwrapped writer")
	}
}
