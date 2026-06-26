package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

const kafkaUIClustersBody = `[{"name":"production","defaultCluster":true,"status":"online",` +
	`"brokerCount":3,"onlinePartitionCount":128,"topicCount":42,"bytesInPerSec":10485.5,` +
	`"bytesOutPerSec":20971.0,"readOnly":false,"version":"3.7.0",` +
	`"features":["TOPIC_DELETION","KAFKA_CONNECT","KSQL_DB"]}]`

const kafdropOverviewBody = `{"summary":{"topicCount":42,"partitionCount":128,` +
	`"underReplicatedCount":0,"preferredReplicaPercent":1.0,"brokerLeaderPartitionCount":{"1":43},` +
	`"brokerPreferredLeaderPartitionCount":{"1":43},"expectedBrokerIds":[1,2,3]},` +
	`"brokers":[{"id":1,"host":"kafka-0.svc.internal","port":9092,"controller":true,"rack":"r1"}],` +
	`"topics":[{"name":"orders","partitions":[]}]}`

func runKafkaModule(t *testing.T, file string, status int, body string) (*modules.Result, http.Header) {
	t.Helper()
	def, err := modules.ParseYAMLModule(file)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
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
	return res, gotHeaders
}

func kafkaExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestKafkaManagementUIExposureModules(t *testing.T) {
	const kafkaUI = "../../modules/recon/kafka-ui-exposure.yaml"
	const kafdrop = "../../modules/recon/kafdrop-exposure.yaml"

	t.Run("an open kafka-ui /api/clusters is flagged with the version", func(t *testing.T) {
		res, _ := runKafkaModule(t, kafkaUI, 200, kafkaUIClustersBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a kafka-ui finding")
		}
		if v := kafkaExtract(res, "kafka_version"); v != "3.7.0" {
			t.Errorf("kafka_version=%q, want 3.7.0", v)
		}
	})

	t.Run("a kafka-ui cluster with a non-enum status is not flagged", func(t *testing.T) {
		body := `[{"name":"x","defaultCluster":true,"status":"degraded","brokerCount":1}]`
		if res, _ := runKafkaModule(t, kafkaUI, 200, body); len(res.Findings) > 0 {
			t.Errorf("a non-enum status should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a login-protected kafka-ui is not flagged", func(t *testing.T) {
		if res, _ := runKafkaModule(t, kafkaUI, 401, `{"message":"Unauthorized"}`); len(res.Findings) > 0 {
			t.Errorf("a 401 kafka-ui should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a kafdrop overview does not match the kafka-ui module", func(t *testing.T) {
		if res, _ := runKafkaModule(t, kafkaUI, 200, kafdropOverviewBody); len(res.Findings) > 0 {
			t.Errorf("a kafdrop body should not match kafka-ui, got %d findings", len(res.Findings))
		}
	})

	t.Run("an open kafdrop overview is flagged with a broker host", func(t *testing.T) {
		res, hdr := runKafkaModule(t, kafdrop, 200, kafdropOverviewBody)
		if len(res.Findings) == 0 {
			t.Fatal("expected a kafdrop finding")
		}
		if v := kafkaExtract(res, "kafka_broker"); v != "kafka-0.svc.internal" {
			t.Errorf("kafka_broker=%q, want kafka-0.svc.internal", v)
		}
		if got := hdr.Get("Accept"); got != "application/json" {
			t.Errorf("Accept header=%q, want application/json", got)
		}
	})

	t.Run("a cluster overview without preferredReplicaPercent is not flagged", func(t *testing.T) {
		body := `{"summary":{"topicCount":1},"brokers":[{"id":1,"host":"h"}],"topics":[]}`
		if res, _ := runKafkaModule(t, kafdrop, 200, body); len(res.Findings) > 0 {
			t.Errorf("a preferredReplicaPercent-less overview should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a basic-auth-protected kafdrop is not flagged", func(t *testing.T) {
		if res, _ := runKafkaModule(t, kafdrop, 401, "Unauthorized"); len(res.Findings) > 0 {
			t.Errorf("a 401 kafdrop should not match, got %d findings", len(res.Findings))
		}
	})

	t.Run("a kafka-ui cluster list does not match the kafdrop module", func(t *testing.T) {
		if res, _ := runKafkaModule(t, kafdrop, 200, kafkaUIClustersBody); len(res.Findings) > 0 {
			t.Errorf("a kafka-ui body should not match kafdrop, got %d findings", len(res.Findings))
		}
	})

	t.Run("plain 200 bodies are not leaks", func(t *testing.T) {
		if res, _ := runKafkaModule(t, kafkaUI, 200, "ok"); len(res.Findings) > 0 {
			t.Errorf("a plain 200 should not match kafka-ui, got %d findings", len(res.Findings))
		}
		if res, _ := runKafkaModule(t, kafdrop, 404, "not found"); len(res.Findings) > 0 {
			t.Errorf("a 404 should not match kafdrop, got %d findings", len(res.Findings))
		}
	})
}
