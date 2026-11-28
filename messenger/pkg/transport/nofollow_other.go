//go:build !unix

package transport

// noFollow is not available on this platform; the journal directory itself
// is checked to be private.
const noFollow = 0
