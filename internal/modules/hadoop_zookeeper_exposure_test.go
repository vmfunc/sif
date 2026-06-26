package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

const zkMonitorBody = `{"command":"monitor","error":null,"version":"3.9.2-a8d7f3e",` +
	`"server_state":"leader","avg_latency":0,"max_latency":12,"min_latency":0,` +
	`"packets_received":1532,"packets_sent":1531,"num_alive_connections":3,` +
	`"outstanding_requests":0,"znode_count":127,"watch_count":4,"ephemerals_count":2,` +
	`"approximate_data_size":45219,"open_file_descriptor_count":67,"max_file_descriptor_count":1048576}`

const nameNodeInfoBody = `{"beans":[{"name":"Hadoop:service=NameNode,name=NameNodeInfo",` +
	`"modelerType":"org.apache.hadoop.hdfs.server.namenode.FSNamesystem",` +
	`"SoftwareVersion":"3.3.6","Version":"3.3.6, rUNKNOWN","Total":2147483648,"Free":1073741824,` +
	`"Safemode":"","ClusterId":"CID-abc123","BlockPoolId":"BP-998-10.0.0.1-170",` +
	`"LiveNodes":"{\"dn1.hdfs.internal:9866\":{\"infoAddr\":\"10.0.0.2:9864\"}}",` +
	`"DeadNodes":"{}","DecomNodes":"{}","TotalBlocks":1024,"TotalFiles":512}]}`

func runHadoopZKModule(t *testing.T, file string, status int, body string) *modules.Result {
	t.Helper()
	def, err := modules.ParseYAMLModule(file)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	res, err := modules.ExecuteHTTPModule(context.Background(), srv.URL, def, modules.Options{
		Timeout: 5 * time.Second,
		Threads: 2,
	})
	if err != nil {
		t.Fatalf("execute %s: %v", file, err)
	}
	return res
}

func hadoopZKExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestHadoopZooKeeperExposureModules(t *testing.T) {
	const zk = "../../modules/recon/zookeeper-admin-exposure.yaml"
	const namenode = "../../modules/recon/hadoop-namenode-exposure.yaml"

	t.Run("an open zookeeper monitor is flagged with the version", func(t *testing.T) {
		res := runHadoopZKModule(t, zk, 200, zkMonitorBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a zookeeper finding")
		}
		if v := hadoopZKExtract(res, "zookeeper_version"); v != "3.9.2-a8d7f3e" {
			t.Errorf("zookeeper_version=%q, want 3.9.2-a8d7f3e", v)
		}
	})

	t.Run("a different adminserver command is not flagged", func(t *testing.T) {
		body := `{"command":"configuration","error":null,"version":"3.9.2","clientPort":2181}`
		if res := runHadoopZKModule(t, zk, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non-monitor command should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a firewalled or absent adminserver is not flagged", func(t *testing.T) {
		if res := runHadoopZKModule(t, zk, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match zookeeper, got %d findings", len(res.Findings))
		}
	})

	t.Run("a namenode jmx body does not match the zookeeper module", func(t *testing.T) {
		if res := runHadoopZKModule(t, zk, 200, nameNodeInfoBody); len(res.Findings) > 0 {
			t.Errorf("a namenode body should not match zookeeper, got %d findings", len(res.Findings))
		}
	})

	t.Run("an open namenode jmx is flagged with the hdfs version", func(t *testing.T) {
		res := runHadoopZKModule(t, namenode, 200, nameNodeInfoBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a namenode finding")
		}
		if v := hadoopZKExtract(res, "hdfs_version"); v != "3.3.6" {
			t.Errorf("hdfs_version=%q, want 3.3.6", v)
		}
	})

	t.Run("a different hadoop jmx bean is not flagged", func(t *testing.T) {
		body := `{"beans":[{"name":"Hadoop:service=DataNode,name=DataNodeInfo",` +
			`"SoftwareVersion":"3.3.6","LiveNodes":"","DeadNodes":""}]}`
		if res := runHadoopZKModule(t, namenode, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non-NameNodeInfo bean should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a kerberos-secured namenode is not flagged", func(t *testing.T) {
		if res := runHadoopZKModule(t, namenode, 401, "Authentication required"); len(res.Findings) > 0 {
			t.Errorf("a 401 namenode should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a zookeeper monitor body does not match the namenode module", func(t *testing.T) {
		if res := runHadoopZKModule(t, namenode, 200, zkMonitorBody); len(res.Findings) > 0 {
			t.Errorf("a zookeeper body should not match namenode, got %d findings", len(res.Findings))
		}
	})

	t.Run("plain 200 bodies are not leaks", func(t *testing.T) {
		if res := runHadoopZKModule(t, zk, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 should not match zookeeper, got %d findings", len(res.Findings))
		}
		if res := runHadoopZKModule(t, namenode, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 should not match namenode, got %d findings", len(res.Findings))
		}
	})
}
