# Percona_MS_NodeLowFreeMemory_RDS_prod Alert Timeline
## June 25, 2026 - Channel: #lcvista-percona (C0931QZ7TFF)

---

## Executive Summary

On June 25, 2026, a **CRITICAL** memory alert was triggered on prod-db-01. Memory usage spiked from 42GB to 96GB between 9:52-9:55 AM EST. The root cause was identified as an unoptimized ad-hoc query run from a django_shell session that performed a full table scan with LIKE '%..%' pattern on the html_body field of the emailnotifications_emailhistory table, causing PostgreSQL to spill ~8.8 GB to temp files during a parallel sort operation.

---

## Timeline (All times in CST / UTC-6)

### **07:59:09 - Initial Alert**
**From:** prasanth.boggarapu (U037N843547)  
**Message:** 
> Hi @here  
> we received **Percona_MS_NodeLowFreeMemory_RDS_prod-db-01 - CRITICAL - Low Free Memory - prod-db-01**.  
> Memory usage increased from 42GB to 96GB between 9:52 AM to 9:55 AM EST.  
> Now usage is normal. I am checking the cause for memory usage and update here.

**Attached:** Screenshot 2026-06-25 at 9.55.16 AM.png

---

### **07:59:57 - Acknowledgment**
**From:** [Team member]
> Please keep us informed. I'm taking look now

---

### **08:00:07 - Response**
**From:** prasanth.boggarapu
> Sure.

---

### **08:02:41 - Recovery Noted**
**From:** [aaron] (U1PMQT6NA)
> Very odd. It appears it has recovered. Can you confirm?

**Attached:** image.png

---

### **08:03:52 - Context on Reports**
**From:** [Team member]
> That's how large reports used to behave last year. I was hopeful we had pushed all that traffic to the replica.

**Thread (3 replies):**
- **08:10:37** - Read replica only enabled for 25 high-usage tenants, CD-931 tracks remaining enablement
- **08:15:57** - "Ah good to know"
- **10:52:52** - Request to pull CD-931 into next sprint

---

### **08:04:20 - Confirmation**
**From:** prasanth.boggarapu
> @aaron Yes. It recovered now.

---

### **08:04:23 - Root Cause Request**
**From:** [Frank Orozco] (U08LY8AR3QT)
> Please let us know the root cause query asap @prasanth boggarapu.

---

### **08:04:33 - Escalation Path**
**From:** [Team member]
> Escalate to @david.gonzalez if needed.

**Thread (11 replies - Detailed investigation):**

#### Thread Reply 1 - 08:52:08
**From:** [Frank Orozco]
> Any update @prasanth boggarapu?

#### Thread Reply 2 - 08:53:09
**From:** prasanth.boggarapu
> @Frank Orozco I see heavy locking on cherrybekaert(accesssharelock) database. I am trying to get the queries and QPS.

#### Thread Reply 3 - 08:54:02
**From:** [Team member]
> are you referring to right now? or during that time?

#### Thread Reply 4 - 08:54:23
**From:** prasanth.boggarapu
> During the time of event

#### Thread Reply 5 - 09:03:31
**From:** prasanth.boggarapu
> @Frank Orozco I'm still investigating the root cause of the memory spike. The memory usage was not consistently high during the event; instead, it fluctuated significantly. My suspicion is that one or more queries were executed repeatedly and completed very quickly. Because these queries finished so fast, they don't appear in the slow query metrics, making them difficult to identify.
> 
> Additionally, the OS-level metrics do not indicate which specific process was consuming the memory, and pg_stat_statements only provides cumulative statistics rather than usage for a specific time window. I need some more time to analyze the PostgreSQL logs and correlate them with the memory spike to identify the query or queries responsible.
> 
> In the meantime, we'll continue monitoring memory usage closely and will let you know if we identify any issues or have further findings.

#### Thread Reply 6 - 09:07:58
**From:** [Team member]
> The locking seemed to occur prior to the event. I see it around 6:48-6:49. @aaron has done some research and this is the leading culprit "a `django_shell` session (PID 26249) from worker node `10.0.0.217`, authenticated as `web_sql@cla`, ran an ad-hoc search over `emailnotifications_emailhistory`. The killer was the final query — it dropped the `to_list`/`sent_time` filters and did `UPPER(html_body::text) LIKE '%...%'` across the whole table plus `ORDER BY sent_time`. With no usable index, Postgres full-scanned every HTML email body and ran a 3-worker **parallel sort that spilled ~8.8 GB across 9 temp files**, running ~4.5 minutes. That spill is your memory + disk I/O spike."

#### Thread Reply 7 - 09:08:24
**From:** [Team member]
> Please confirm. Please also escalate to @david.gonzalez when he is online.

#### Thread Reply 8 - 09:08:53
**From:** prasanth.boggarapu
> @Frank Orozco Sure

#### Thread Reply 9 - 11:05:24
**From:** prasanth.boggarapu
> @Frank Orozco Sorry for delay. I had to jump to different issue.
> it's already confirmed by Aaron and Matheus. Since you asked us to confirm, yes memory utilization was spiked due to below query.
> 
> The reasons mentioned by Aaron are correct. The Like '%%' pattern, combined with UPPER(), stopped PostgreSQL from using index, causing the planner to choose a sequential scan. The ORDER BY then triggered a sort, which spilled to temporary files and contributed to the memory/temp usage spike.

**Problematic Query:**
```sql
SELECT
    "emailnotifications_emailhistory"."id" AS "id",
    "emailnotifications_emailhistory"."sent_time" AS "sent_time",
    "emailnotifications_emailhistory"."subject" AS "subject",
    "emailnotifications_emailhistory"."email_type" AS "email_type",
    "emailnotifications_emailhistory"."to_list" AS "to_list",
    "emailnotifications_emailhistory"."manual_user_id" AS "manual_user_id",
    "emailnotifications_emailhistory"."notification_template_id" AS "notification_template_id"
FROM
    "emailnotifications_emailhistory"
    LEFT OUTER JOIN "learning_program" ON ("emailnotifications_emailhistory"."program_id" = "learning_program"."id")
WHERE ("learning_program"."alternate_id" = '4168202'
    OR UPPER("emailnotifications_emailhistory"."html_body"::text)
    LIKE UPPER('%4168202%')
    OR UPPER("emailnotifications_emailhistory"."html_body"::text)
    LIKE UPPER('%a077ba4b-deb8-429a-b180-4bcdaa757335%'))
ORDER BY
    2 ASC
LIMIT 21;
```

**Query Details:**
- Date: 2026-06-25 13:54:28 UTC (6:54:28 AM CST)
- Duration: 4m31s
- Database: cla
- User: web_sql
- Remote: 10.0.0.217
- Log file: postgresql.log.2026-06-25-13

**Confirmation notes:**
1. No problem ticket needed - one-time incident with identified cause
2. Query ran for 4.31 minutes, but long-running alert threshold is 8 minutes (hence no alert)

#### Thread Reply 10 - 11:05:58
**From:** [Team member]
> Confirmed

#### Thread Reply 11 - 12:06:40
**From:** david.gonzalez (U01NAEEQMDH)
> Hi @Frank Orozco, team,
> I just reviewed this thread and the related messages in the channel. I agree with the diagnosis based on the collected evidence. Column `public.emailnotifications_emailhistory.html_body` is a text data type, and there are no indexes on it; even if there were a regular B-tree index, it would not be used because of the `LIKE (%%)` operator.
> As @prasanth boggarapu described, the query patterns increased resource consumption.
> If collecting the data this query aims to gather is required, one option is to consider trigram indexes (pg_trgm), which can be `GIN` (faster for reads, larger in size) or `GiST` (faster for writes, smaller in size). Even if queries like this are directed to the replica, they can impact its performance if they are run without the proper indexes.
> As always, any schema/workload adjustment should be verified on a lower environment first.

---

### **08:04:42 - Acknowledgment**
**From:** prasanth.boggarapu
> @Frank Orozco Sure. I will update here ASAP.

---

### **09:31:03 - Root Cause Admission**
**From:** [Matheus Araujo] (U06P23KFBDX)
> Hey everybody! Good morning!
> I had to run a query this morning to search for emails related to a program in CLA.
> Now that I thought about it, CLA's dataset is too big and my query was not optimal for that. This probably caused the increase you're all seeing.
> As I was speaking to Sam, currently, there's not a way for us to search for information in production data so we can properly address support tickets. We used to have the snapshots, but those are deactivated now.
> Again, sorry for this incident!
> @sam_estrem and I agreed developers should keep away from shelling into production. I'll address this in today's standup so we can let tech leadership team know we need prod data from now on.

**Thread (2 replies - Process improvement discussion):**

#### Thread Reply 1 - 11:01:38
**From:** [Team member]
> Hi @Matheus Araujo! For future reference:
> Although it would be ideal to have prod data available somewhere else to not interact with the prod db, sometimes it's not possible (like this scenario you described) and you still have to get it directly from prod. If that's the case, the priority should always be minimizing the disruption on the environment. For a one-time things like getting a specific value from a table for troubleshooting or something that's not part of a recurring process, like this case where you wanted to search into a string field with a `LIKE '%...%'` clause, you might benefit from getting the data with the simplest and most minimal `SELECT` you can run, and once you have the data retrieved, process it locally somehow (e.g.: A Python/JS/whatever script, opening the query result in VS Code and looking for the string in the search tool, etc.) to get the result you want without affecting the prod db performance.

#### Thread Reply 2 - 11:25:17
**From:** [Team member]
> These are good points, but I want to bring the focus back to the main question about when/how it's appropriate
> 1. If you think you need to run a script in prod, **please escalate to tech management for approval**
>     a. This allows us to help determine if there's an alternate safer way to get the data
>     b. This helps track pain points preventing developers from safely debugging to guide future internal tools and processes
> 2. If you get approval to run prod shell commands
>     a. always screen share with another dev (preferably Sam, Robin, Aaron, Frank B, or Frank O)
>     b. pre-write all scripts and test on staging/pr-env first
>     c. Get sign-off on script from all people on the call prior to running
>     d. Document all scripts and results in the ticket being addressed

---

### **15:26:02 - Separate Long-Running Query Alert**
**From:** Neha Korukula (U040ZTH138W)
> Hello @here
> We received an alert for Long running active query - (database cretepa@prod-db-01) upon checking, could see below query running in 26 sessions is causing few blockings/lock conflicts.

**Query Details:** 27 rows of long-running SELECT queries on `compliance_compliancestatelock` table with FOR UPDATE locks, causing tuple-level locking conflicts. Query times ranged from ~11:42 to ~11:58 minutes.

**Blocking Details:**
- Process 21369 (idletx state) blocking 23 queries
- Process 21450 (active state) blocking 22 queries
- Overall CPU utilization not impacted
- Tenant: cretepa

**Attached:** Screenshot 2026-06-25 at 2.24.35 PM.png

**Thread (2 replies):**

#### Thread Reply 1 - 15:27:16
**From:** Neha Korukula
> FYI! Now the query seems completed and alert is resolved.
> 
> (Shows 0 rows for both running queries and blockings)

#### Thread Reply 2 - 15:27:47
**From:** [Team member]
> Thank you!

---

## Related Context (June 26)

### **June 26, 03:14:39 - Similar Alert for Different Database**
**From:** Sonia Valeja (U030LJXKQU9)
> Hi Team - We have received an alert `PagerDuty: Percona_MS_PostgresqlQueryDuration_state_in_active - WARNING - Long running active query - (database rsmus@prod-db-01)`. More details in the thread. Thanks

**Thread:** 6 replies (latest: 2026-06-26 03:17:11 CST)

### **June 26, 07:26:20 - Another Long-Running Query Alert**
**From:** Ninad Shah (U030D7Q86BX)
> @here we have received an alert(INC0334786) for long-running queries on prod-db-01. We are looking into it and get back to you.

**Thread:** 5 replies

### **June 26, 08:58:34 - cretepa Database Alert**
**From:** Ninad Shah
> I received the same alert again but for cretepa database.
> Below is the details of blockers.
> 
> (24 rows of blocking queries on `compliance_compliancestatelock` table)
> 
> Kindly let us know if we can ignore these alerts.

---

## Key Technical Findings

### Root Cause Analysis
1. **Trigger:** Ad-hoc django_shell query from developer searching for emails related to a program
2. **Problem Query Characteristics:**
   - Used `UPPER(html_body::text) LIKE UPPER('%...%')` pattern
   - No usable index on text column
   - Forced full table scan of all email bodies
   - Combined with `ORDER BY sent_time`
3. **PostgreSQL Response:**
   - Launched 3-worker parallel sort
   - Spilled ~8.8 GB across 9 temp files
   - Duration: ~4.5 minutes (4m31s recorded)
   - Peak memory: 96GB (from baseline 42GB)

### Why No Long-Running Query Alert?
- Query ran for 4m31s
- Alert threshold: 8 minutes
- Query completed before threshold

### Recommended Solutions (from david.gonzalez)
If similar queries are required in the future:
- Consider **trigram indexes (pg_trgm)** on text fields
  - **GIN index:** Faster for reads, larger size
  - **GiST index:** Faster for writes, smaller size
- Route such queries to read replica (when appropriate)
- Test schema/workload changes on lower environments first

### Process Improvements Identified
1. Developers need access to prod data snapshots for debugging
2. If prod access is necessary:
   - Escalate to tech management for approval
   - Screen share with senior dev during execution
   - Pre-write and test scripts on staging
   - Get sign-off before running
   - Document all scripts and results
3. For one-time data retrieval:
   - Use simplest SELECT possible
   - Process/filter data locally after retrieval
   - Avoid complex WHERE/LIKE clauses on large text fields

---

## Action Items

- [x] Root cause identified
- [x] Memory spike resolved (returned to normal)
- [x] Developer acknowledged and proposed process improvements
- [ ] Evaluate need for pg_trgm indexes on emailnotifications_emailhistory.html_body
- [ ] Implement prod data snapshot access for developers (address in standup)
- [ ] Pull CD-931 (read replica enablement) into next sprint

---

## Incident Classification

**Severity:** CRITICAL (memory alert)  
**Impact:** Temporary (9:52-9:55 AM EST, ~3 minutes)  
**Resolution:** Self-recovering  
**Problem Ticket:** None (one-time incident with identified cause)

---

_Timeline compiled from Slack channel #lcvista-percona (C0931QZ7TFF) on June 30, 2026_
