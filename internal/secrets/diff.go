package secrets

// diffLines is a line diff of two small texts: unchanged lines keep a
// leading space, removed lines a minus, added lines a plus.
func diffLines(before, after []string) []string {
	n, m := len(before), len(after)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if before[i] == after[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	var out []string
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case before[i] == after[j]:
			out = append(out, " "+before[i])
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, "-"+before[i])
			i++
		default:
			out = append(out, "+"+after[j])
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, "-"+before[i])
	}
	for ; j < m; j++ {
		out = append(out, "+"+after[j])
	}
	return out
}
