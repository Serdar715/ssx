// ------------------------------------------------------
// Shortscan v2 - Levenshtein Distance
// Optimized implementation for fuzzy matching
// ------------------------------------------------------

package levenshtein

// Distance returns the Levenshtein edit distance for two strings
// Uses dynamic programming with space optimization
func Distance(a, b string) int {
	// Convert to rune slices for proper Unicode handling
	ra := []rune(a)
	rb := []rune(b)
	
	la := len(ra)
	lb := len(rb)
	
	// Handle edge cases
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	
	// Swap to ensure b is shorter (optimization)
	if la < lb {
		ra, rb = rb, ra
		la, lb = lb, la
	}
	
	// Use single row optimization (O(min(m,n)) space)
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	
	// Initialize first row
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	
	// Calculate edit distances
	for i := 1; i <= la; i++ {
		curr[0] = i
		
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			
			// Minimum of insert, delete, replace
			curr[j] = min3(
				prev[j]+1,      // deletion
				curr[j-1]+1,    // insertion
				prev[j-1]+cost, // substitution
			)
		}
		
		// Swap rows
		prev, curr = curr, prev
	}
	
	return prev[lb]
}

// DistanceThreshold calculates distance but stops early if threshold exceeded
func DistanceThreshold(a, b string, threshold int) int {
	ra := []rune(a)
	rb := []rune(b)
	
	la := len(ra)
	lb := len(rb)
	
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	
	// Early exit if difference in length exceeds threshold
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	if diff > threshold {
		return threshold + 1
	}
	
	// Standard calculation
	d := Distance(a, b)
	if d > threshold {
		return threshold + 1
	}
	return d
}

// Ratio returns the similarity ratio between two strings (0.0 to 1.0)
func Ratio(a, b string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	
	maxLen := max(len(a), len(b))
	if maxLen == 0 {
		return 1.0
	}
	
	distance := Distance(a, b)
	return 1.0 - float64(distance)/float64(maxLen)
}

// SimilarityCheck checks if two strings are similar within a threshold
func SimilarityCheck(a, b string, threshold float64) bool {
	return Ratio(a, b) >= threshold
}

// Helper functions
func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
