package encrypt

import (
	"bytes"
	"strings"
	"testing"

	secerrors "github.com/Dorico-Dynamics/txova-go-security"
)

func TestNew(t *testing.T) {
	t.Run("creates cipher with valid key", func(t *testing.T) {
		key := make([]byte, KeySize)
		cipher, err := New("primary", key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cipher == nil {
			t.Fatal("expected cipher, got nil")
		}
		if cipher.PrimaryKeyID() != "primary" {
			t.Errorf("expected primary key ID 'primary', got %q", cipher.PrimaryKeyID())
		}
	})

	t.Run("rejects empty key ID", func(t *testing.T) {
		key := make([]byte, KeySize)
		_, err := New("", key)
		if err == nil {
			t.Fatal("expected error for empty key ID")
		}
		if !secerrors.IsInvalidKey(err) {
			t.Errorf("expected InvalidKey error, got: %v", err)
		}
	})

	t.Run("rejects invalid key size", func(t *testing.T) {
		tests := []int{0, 1, 15, 16, 24, 31, 33, 64}
		for _, size := range tests {
			key := make([]byte, size)
			_, err := New("primary", key)
			if err == nil {
				t.Errorf("expected error for key size %d", size)
			}
			if !secerrors.IsInvalidKey(err) {
				t.Errorf("expected InvalidKey error for size %d, got: %v", size, err)
			}
		}
	})
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	cipher, err := New("test-key", key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	t.Run("round trip various sizes", func(t *testing.T) {
		testCases := [][]byte{
			[]byte(""),
			[]byte("a"),
			[]byte("hello"),
			[]byte("Hello, World!"),
			bytes.Repeat([]byte("x"), 100),
			bytes.Repeat([]byte("y"), 1000),
			bytes.Repeat([]byte("z"), 10000),
		}

		for _, plaintext := range testCases {
			encrypted, err := cipher.Encrypt(plaintext)
			if err != nil {
				t.Errorf("encryption failed for len=%d: %v", len(plaintext), err)
				continue
			}

			decrypted, err := cipher.Decrypt(encrypted)
			if err != nil {
				t.Errorf("decryption failed for len=%d: %v", len(plaintext), err)
				continue
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("decrypted data mismatch for len=%d", len(plaintext))
			}
		}
	})

	t.Run("unique nonce per encryption", func(t *testing.T) {
		plaintext := []byte("same plaintext")
		encrypted1, _ := cipher.Encrypt(plaintext)
		encrypted2, _ := cipher.Encrypt(plaintext)

		// Same plaintext should produce different ciphertext due to unique nonces
		if encrypted1 == encrypted2 {
			t.Error("expected different ciphertext for same plaintext (nonce should be unique)")
		}

		// Both should decrypt to the same plaintext
		decrypted1, _ := cipher.Decrypt(encrypted1)
		decrypted2, _ := cipher.Decrypt(encrypted2)

		if !bytes.Equal(decrypted1, plaintext) || !bytes.Equal(decrypted2, plaintext) {
			t.Error("decryption should produce same plaintext")
		}
	})

	t.Run("ciphertext format", func(t *testing.T) {
		encrypted, _ := cipher.Encrypt([]byte("test"))

		parts := strings.Split(encrypted, ":")
		if len(parts) != 3 {
			t.Errorf("expected 3 parts (key_id:nonce:ciphertext), got %d", len(parts))
		}

		if parts[0] != "test-key" {
			t.Errorf("expected key ID 'test-key', got %q", parts[0])
		}
	})
}

func TestDecrypt_InvalidInput(t *testing.T) {
	key := make([]byte, KeySize)
	cipher, _ := New("test-key", key)

	t.Run("invalid format - no separator", func(t *testing.T) {
		_, err := cipher.Decrypt("invaliddatawithoutseparators")
		if err == nil {
			t.Fatal("expected error for invalid format")
		}
		if !secerrors.IsDecryptionFailed(err) {
			t.Errorf("expected DecryptionFailed error, got: %v", err)
		}
	})

	t.Run("invalid format - wrong parts", func(t *testing.T) {
		_, err := cipher.Decrypt("only:two")
		if err == nil {
			t.Fatal("expected error for invalid format")
		}
	})

	t.Run("unknown key ID", func(t *testing.T) {
		_, err := cipher.Decrypt("unknown-key:bm9uY2U:Y2lwaGVydGV4dA")
		if err == nil {
			t.Fatal("expected error for unknown key ID")
		}
		if !secerrors.IsDecryptionFailed(err) {
			t.Errorf("expected DecryptionFailed error, got: %v", err)
		}
	})

	t.Run("invalid nonce encoding", func(t *testing.T) {
		_, err := cipher.Decrypt("test-key:!!!invalid!!!:Y2lwaGVydGV4dA")
		if err == nil {
			t.Fatal("expected error for invalid nonce")
		}
	})

	t.Run("invalid ciphertext encoding", func(t *testing.T) {
		_, err := cipher.Decrypt("test-key:bm9uY2U:!!!invalid!!!")
		if err == nil {
			t.Fatal("expected error for invalid ciphertext")
		}
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		encrypted, _ := cipher.Encrypt([]byte("secret data"))

		// Tamper with the ciphertext
		tampered := encrypted[:len(encrypted)-2] + "XX"

		_, err := cipher.Decrypt(tampered)
		if err == nil {
			t.Fatal("expected error for tampered ciphertext")
		}
		if !secerrors.IsDecryptionFailed(err) {
			t.Errorf("expected DecryptionFailed error, got: %v", err)
		}
	})

	t.Run("invalid nonce size", func(t *testing.T) {
		// Create valid-looking but wrong nonce size
		_, err := cipher.Decrypt("test-key:YWJj:Y2lwaGVydGV4dA") // "abc" is only 3 bytes
		if err == nil {
			t.Fatal("expected error for invalid nonce size")
		}
	})
}

func TestKeyRotation(t *testing.T) {
	key1 := make([]byte, KeySize)
	key2 := make([]byte, KeySize)
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 100)
	}

	t.Run("encrypt with old key decrypt with old key", func(t *testing.T) {
		cipher, _ := New("key-v1", key1)

		encrypted, _ := cipher.Encrypt([]byte("secret"))
		decrypted, err := cipher.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}
		if string(decrypted) != "secret" {
			t.Error("decrypted data mismatch")
		}
	})

	t.Run("add new key and decrypt old data", func(t *testing.T) {
		cipher, _ := New("key-v1", key1)

		// Encrypt with v1
		encryptedV1, _ := cipher.Encrypt([]byte("data from v1"))

		// Add v2 key
		if err := cipher.AddKey("key-v2", key2); err != nil {
			t.Fatalf("failed to add key: %v", err)
		}

		// Should still be able to decrypt v1 data
		decrypted, err := cipher.Decrypt(encryptedV1)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}
		if string(decrypted) != "data from v1" {
			t.Error("decrypted data mismatch")
		}
	})

	t.Run("rotate primary and encrypt with new key", func(t *testing.T) {
		cipher, _ := New("key-v1", key1)

		// Encrypt with v1
		encryptedV1, _ := cipher.Encrypt([]byte("old data"))

		// Add and set v2 as primary
		_ = cipher.AddKey("key-v2", key2)
		if err := cipher.SetPrimaryKey("key-v2"); err != nil {
			t.Fatalf("failed to set primary key: %v", err)
		}

		// Encrypt with v2
		encryptedV2, _ := cipher.Encrypt([]byte("new data"))

		// Verify correct key IDs in ciphertext
		if !strings.HasPrefix(encryptedV1, "key-v1:") {
			t.Error("v1 ciphertext should use key-v1")
		}
		if !strings.HasPrefix(encryptedV2, "key-v2:") {
			t.Error("v2 ciphertext should use key-v2")
		}

		// Both should decrypt successfully
		decryptedV1, _ := cipher.Decrypt(encryptedV1)
		decryptedV2, _ := cipher.Decrypt(encryptedV2)

		if string(decryptedV1) != "old data" {
			t.Error("v1 decryption mismatch")
		}
		if string(decryptedV2) != "new data" {
			t.Error("v2 decryption mismatch")
		}
	})

	t.Run("set unknown primary key fails", func(t *testing.T) {
		cipher, _ := New("key-v1", key1)

		err := cipher.SetPrimaryKey("nonexistent")
		if err == nil {
			t.Fatal("expected error for unknown key")
		}
		if !secerrors.IsInvalidKey(err) {
			t.Errorf("expected InvalidKey error, got: %v", err)
		}
	})
}

func TestAddKey(t *testing.T) {
	key1 := make([]byte, KeySize)
	cipher, _ := New("primary", key1)

	t.Run("add valid key", func(t *testing.T) {
		key2 := make([]byte, KeySize)
		for i := range key2 {
			key2[i] = byte(i + 50)
		}

		err := cipher.AddKey("secondary", key2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !cipher.HasKey("secondary") {
			t.Error("key should exist after adding")
		}
	})

	t.Run("reject empty key ID", func(t *testing.T) {
		key := make([]byte, KeySize)
		err := cipher.AddKey("", key)
		if err == nil {
			t.Fatal("expected error for empty key ID")
		}
	})

	t.Run("reject invalid key size", func(t *testing.T) {
		err := cipher.AddKey("bad", make([]byte, 16))
		if err == nil {
			t.Fatal("expected error for invalid key size")
		}
	})
}

func TestEncryptDecryptField(t *testing.T) {
	key := make([]byte, KeySize)
	cipher, _ := New("test", key)

	t.Run("empty string", func(t *testing.T) {
		encrypted, err := cipher.EncryptField("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if encrypted != "" {
			t.Error("expected empty string for empty input")
		}

		decrypted, err := cipher.DecryptField("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decrypted != "" {
			t.Error("expected empty string for empty input")
		}
	})

	t.Run("round trip string field", func(t *testing.T) {
		original := "sensitive data like SSN or email"

		encrypted, err := cipher.EncryptField(original)
		if err != nil {
			t.Fatalf("encryption failed: %v", err)
		}

		decrypted, err := cipher.DecryptField(encrypted)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}

		if decrypted != original {
			t.Errorf("expected %q, got %q", original, decrypted)
		}
	})
}

func TestHasKey(t *testing.T) {
	key := make([]byte, KeySize)
	cipher, _ := New("primary", key)

	if !cipher.HasKey("primary") {
		t.Error("should have primary key")
	}

	if cipher.HasKey("nonexistent") {
		t.Error("should not have nonexistent key")
	}
}

func TestKeyIDs(t *testing.T) {
	key1 := make([]byte, KeySize)
	key2 := make([]byte, KeySize)
	for i := range key2 {
		key2[i] = byte(i + 1)
	}

	cipher, _ := New("key-a", key1)
	_ = cipher.AddKey("key-b", key2)

	ids := cipher.KeyIDs()
	if len(ids) != 2 {
		t.Errorf("expected 2 key IDs, got %d", len(ids))
	}

	// Check both keys are present (order may vary)
	hasA, hasB := false, false
	for _, id := range ids {
		if id == "key-a" {
			hasA = true
		}
		if id == "key-b" {
			hasB = true
		}
	}
	if !hasA || !hasB {
		t.Errorf("missing expected key IDs: %v", ids)
	}
}

func TestGenerateKey(t *testing.T) {
	t.Run("generates correct size", func(t *testing.T) {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(key) != KeySize {
			t.Errorf("expected key size %d, got %d", KeySize, len(key))
		}
	})

	t.Run("generates unique keys", func(t *testing.T) {
		keys := make(map[string]struct{})
		for i := 0; i < 100; i++ {
			key, _ := GenerateKey()
			keyStr := string(key)
			if _, exists := keys[keyStr]; exists {
				t.Error("generated duplicate key")
			}
			keys[keyStr] = struct{}{}
		}
	})

	t.Run("can use generated key", func(t *testing.T) {
		key, _ := GenerateKey()
		cipher, err := New("generated", key)
		if err != nil {
			t.Fatalf("failed to create cipher with generated key: %v", err)
		}

		encrypted, _ := cipher.Encrypt([]byte("test"))
		decrypted, err := cipher.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("decryption failed: %v", err)
		}
		if string(decrypted) != "test" {
			t.Error("decrypted data mismatch")
		}
	})
}

func TestConcurrency(t *testing.T) {
	key := make([]byte, KeySize)
	cipher, _ := New("test", key)

	// Run concurrent encryptions and decryptions
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				plaintext := []byte("concurrent test data")
				encrypted, err := cipher.Encrypt(plaintext)
				if err != nil {
					t.Errorf("goroutine %d: encryption failed: %v", id, err)
					continue
				}

				decrypted, err := cipher.Decrypt(encrypted)
				if err != nil {
					t.Errorf("goroutine %d: decryption failed: %v", id, err)
					continue
				}

				if !bytes.Equal(decrypted, plaintext) {
					t.Errorf("goroutine %d: data mismatch", id)
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func BenchmarkEncrypt(b *testing.B) {
	key := make([]byte, KeySize)
	cipher, _ := New("bench", key)
	plaintext := []byte("benchmark test data for encryption")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cipher.Encrypt(plaintext)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	key := make([]byte, KeySize)
	cipher, _ := New("bench", key)
	encrypted, _ := cipher.Encrypt([]byte("benchmark test data for decryption"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cipher.Decrypt(encrypted)
	}
}

func BenchmarkEncryptDecrypt(b *testing.B) {
	key := make([]byte, KeySize)
	cipher, _ := New("bench", key)
	plaintext := []byte("benchmark test data for round trip")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := cipher.Encrypt(plaintext)
		_, _ = cipher.Decrypt(encrypted)
	}
}
