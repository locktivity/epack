package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/locktivity/epack/internal/cli/output"
	"github.com/locktivity/epack/internal/jobs"
	"github.com/locktivity/epack/internal/project"
	"github.com/spf13/cobra"
)

var (
	jobsAll   bool
	jobsClean bool
)

func init() {
	rootCmd.AddCommand(jobsCmd)

	jobsCmd.Flags().BoolVarP(&jobsAll, "all", "a", false, "show all jobs (including completed)")
	jobsCmd.Flags().BoolVar(&jobsClean, "clean", false, "remove completed job records older than 24 hours")
}

var jobsCmd = &cobra.Command{
	Use:   "jobs [job-id]",
	Short: "List or inspect background jobs",
	Long: `List background jobs or inspect a specific job.

When run without arguments, lists all running background jobs.
When given a job ID, shows detailed status of that job.

Examples:
  # List running jobs
  epack jobs

  # List all jobs (including completed)
  epack jobs --all

  # Show details of a specific job
  epack jobs job_20240221_143052_12345

  # Clean up old completed jobs
  epack jobs --clean`,
	Args: cobra.MaximumNArgs(1),
	RunE: runJobs,
}

func runJobs(cmd *cobra.Command, args []string) error {
	out := outputWriter()

	// Find project root for job storage
	projectRoot, err := project.FindRoot("")
	if err != nil {
		// Fall back to current directory
		projectRoot, _ = os.Getwd()
	}

	// Create job manager
	jobsDir := filepath.Join(projectRoot, ".epack", "jobs")
	mgr := jobs.NewManager(jobsDir)

	// Clean mode
	if jobsClean {
		removed, err := mgr.Clean(24 * 60 * 60 * 1000000000) // 24 hours in nanoseconds
		if err != nil {
			return exitError("failed to clean jobs: %v", err)
		}
		if out.IsJSON() {
			return out.JSON(map[string]interface{}{
				"cleaned": removed,
			})
		}
		out.Success("Cleaned %d old job(s)", removed)
		return nil
	}

	// Show specific job
	if len(args) == 1 {
		return showJob(mgr, args[0], out)
	}

	// List jobs
	var statusFilter jobs.Status
	if !jobsAll {
		statusFilter = jobs.StatusRunning
	}

	jobList, err := mgr.List(statusFilter)
	if err != nil {
		return exitError("failed to list jobs: %v", err)
	}

	if out.IsJSON() {
		jobsData := make([]map[string]interface{}, len(jobList))
		for i, job := range jobList {
			jobsData[i] = map[string]interface{}{
				"id":         job.ID,
				"command":    job.Command,
				"args":       job.Args,
				"status":     job.Status,
				"pid":        job.PID,
				"started_at": job.StartedAt,
				"log_path":   job.LogPath,
			}
			if job.CompletedAt != nil {
				jobsData[i]["completed_at"] = job.CompletedAt
			}
			if job.ExitCode != nil {
				jobsData[i]["exit_code"] = *job.ExitCode
			}
			if job.Error != "" {
				jobsData[i]["error"] = job.Error
			}
		}
		return out.JSON(map[string]interface{}{
			"jobs": jobsData,
		})
	}

	if len(jobList) == 0 {
		if jobsAll {
			out.Print("No jobs found.\n")
		} else {
			out.Print("No running jobs.\n")
			out.Print("  Use --all to show completed jobs.\n")
		}
		return nil
	}

	palette := out.Palette()
	out.Print("%s\n", palette.Bold("Background Jobs:"))
	out.Print("\n")

	for _, job := range jobList {
		statusIcon := statusToIcon(job.Status, palette)
		out.Print("  %s %s\n", statusIcon, job.ID)
		out.Print("      Command: epack %s %s\n", job.Command, strings.Join(job.Args, " "))
		out.Print("      Started: %s\n", formatTimeAgo(job.StartedAt))
		if job.Status == jobs.StatusRunning {
			out.Print("      PID:     %d\n", job.PID)
		}
		if job.CompletedAt != nil {
			out.Print("      Finished: %s\n", formatTimeAgo(*job.CompletedAt))
		}
		if job.ExitCode != nil && *job.ExitCode != 0 {
			out.Print("      Exit:    %d\n", *job.ExitCode)
		}
		if job.Error != "" {
			out.Print("      Error:   %s\n", job.Error)
		}
		out.Print("\n")
	}

	return nil
}

func showJob(mgr *jobs.Manager, jobID string, out *output.Writer) error {
	job, err := mgr.Load(jobID)
	if err != nil {
		return exitError("job not found: %s", jobID)
	}

	if out.IsJSON() {
		data := map[string]interface{}{
			"id":         job.ID,
			"command":    job.Command,
			"args":       job.Args,
			"status":     job.Status,
			"pid":        job.PID,
			"started_at": job.StartedAt,
			"log_path":   job.LogPath,
		}
		if job.CompletedAt != nil {
			data["completed_at"] = job.CompletedAt
		}
		if job.ExitCode != nil {
			data["exit_code"] = *job.ExitCode
		}
		if job.Error != "" {
			data["error"] = job.Error
		}
		if job.Result != nil {
			data["result"] = job.Result
		}
		return out.JSON(data)
	}

	palette := out.Palette()
	statusIcon := statusToIcon(job.Status, palette)

	out.Print("%s %s\n\n", statusIcon, palette.Bold(job.ID))

	out.Print("%s\n", palette.Bold("Details:"))
	out.Print("  Command:  epack %s %s\n", job.Command, strings.Join(job.Args, " "))
	out.Print("  Status:   %s\n", job.Status)
	out.Print("  PID:      %d\n", job.PID)
	out.Print("  Started:  %s\n", job.StartedAt.Format("2006-01-02 15:04:05"))

	if job.CompletedAt != nil {
		out.Print("  Finished: %s\n", job.CompletedAt.Format("2006-01-02 15:04:05"))
		duration := job.CompletedAt.Sub(job.StartedAt)
		out.Print("  Duration: %s\n", duration.Round(100*1000000).String()) // Round to 100ms
	}

	if job.ExitCode != nil {
		out.Print("  Exit:     %d\n", *job.ExitCode)
	}

	if job.Error != "" {
		out.Print("\n%s\n", palette.Bold("Error:"))
		out.Print("  %s\n", job.Error)
	}

	out.Print("\n%s\n", palette.Bold("Log:"))
	out.Print("  %s\n", job.LogPath)

	// Show last few lines of log if available
	if job.LogPath != "" {
		if data, err := os.ReadFile(job.LogPath); err == nil {
			lines := strings.Split(string(data), "\n")
			// Show last 10 lines
			start := len(lines) - 10
			if start < 0 {
				start = 0
			}
			if start < len(lines) {
				out.Print("\n%s\n", palette.Bold("Recent output:"))
				for _, line := range lines[start:] {
					if line != "" {
						out.Print("  %s\n", line)
					}
				}
			}
		}
	}

	return nil
}

func statusToIcon(status jobs.Status, palette *output.Palette) string {
	switch status {
	case jobs.StatusRunning:
		return palette.Yellow("◉")
	case jobs.StatusCompleted:
		return palette.Green("✓")
	case jobs.StatusFailed:
		return palette.Red("✗")
	default:
		return "○"
	}
}

// formatTimeAgo formats a time as a human-readable "X ago" string.
func formatTimeAgo(t time.Time) string {
	d := time.Since(t)

	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		mins := int(d.Minutes())
		if mins == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", mins)
	case d < 24*time.Hour:
		hours := int(d.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	case d < 7*24*time.Hour:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	default:
		return t.Format("2006-01-02 15:04")
	}
}
