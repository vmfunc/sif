package modules_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vmfunc/sif/internal/modules"
)

func runImageGenModule(t *testing.T, file string, status int, body string) *modules.Result {
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

func imageGenExtract(res *modules.Result, key string) string {
	for _, f := range res.Findings {
		if v := f.Extracted[key]; v != "" {
			return v
		}
	}
	return ""
}

func TestImageGenExposureModules(t *testing.T) {
	const comfyui = "../../modules/recon/comfyui-api-exposure.yaml"
	const a1111 = "../../modules/recon/automatic1111-api-exposure.yaml"
	const fooocus = "../../modules/recon/fooocus-api-exposure.yaml"
	const iopaint = "../../modules/recon/iopaint-api-exposure.yaml"

	comfyStats := `{"system":{"os":"posix","ram_total":67430219776,"ram_free":12345678,` +
		`"comfyui_version":"0.3.40","python_version":"3.11.9","pytorch_version":"2.3.1",` +
		`"embedded_python":false,"argv":["main.py"]},"devices":[{"name":"cuda:0 NVIDIA RTX 4090",` +
		`"type":"cuda","index":0,"vram_total":25757220864,"vram_free":24000000000,` +
		`"torch_vram_total":268435456,"torch_vram_free":260000000}]}`

	a1111Models := `[{"title":"sd_xl_base_1.0.safetensors [31e35c80fc]","model_name":"sd_xl_base_1.0",` +
		`"hash":"31e35c80fc","sha256":"31e35c80fc4829d14f90153f4c74cd59c90b779f6afe05a74cd6120b893f7e5b",` +
		`"filename":"/home/sd/models/Stable-diffusion/sd_xl_base_1.0.safetensors","config":null}]`

	fooocusModels := `{"model_filenames":["juggernautXL_v8.safetensors","sd_xl_base_1.0.safetensors"],` +
		`"lora_filenames":["sdxl_lcm_lora.safetensors"]}`

	iopaintConfig := `{"plugins":[{"name":"RemoveBG","support_gen_image":true,"support_gen_mask":false}],` +
		`"modelInfos":[{"name":"lama","path":"lama","model_type":"inpaint"}],` +
		`"removeBGModel":"briaai/RMBG-1.4","removeBGModels":["briaai/RMBG-1.4","u2net"],` +
		`"realesrganModel":"realesr-general-x4v3","realesrganModels":["realesr-general-x4v3"],` +
		`"interactiveSegModel":"sam2_1_tiny","interactiveSegModels":["vit_b","sam2_1_tiny"],` +
		`"enableFileManager":true,"enableAutoSaving":false,"enableControlnet":false,` +
		`"controlnetMethod":null,"disableModelSwitch":false,"isDesktop":false,` +
		`"samplers":["DPM++ 2M","Euler","Euler a"]}`

	t.Run("a comfyui system_stats is flagged with its version", func(t *testing.T) {
		res := runImageGenModule(t, comfyui, 200, comfyStats)
		if len(res.Findings) == 0 {
			t.Fatal("expected a comfyui finding")
		}
		if v := imageGenExtract(res, "comfyui_version"); v != "0.3.40" {
			t.Errorf("comfyui_version=%q, want 0.3.40", v)
		}
	})

	t.Run("a system_stats without comfyui keys is not flagged", func(t *testing.T) {
		body := `{"system":{"os":"linux","ram_total":123},"devices":[]}`
		if res := runImageGenModule(t, comfyui, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic system stats should not match comfyui, got %d findings", len(res.Findings))
		}
	})

	t.Run("a comfyui version without device memory is not flagged", func(t *testing.T) {
		body := `{"system":{"comfyui_version":"0.3.40"}}`
		if res := runImageGenModule(t, comfyui, 200, body); len(res.Findings) > 0 {
			t.Errorf("a version-only body should not match comfyui, got %d findings", len(res.Findings))
		}
	})

	t.Run("an automatic1111 sd-models list is flagged with its checkpoint", func(t *testing.T) {
		res := runImageGenModule(t, a1111, 200, a1111Models)
		if len(res.Findings) == 0 {
			t.Fatal("expected an automatic1111 finding")
		}
		if v := imageGenExtract(res, "sd_model_name"); v != "sd_xl_base_1.0" {
			t.Errorf("sd_model_name=%q, want sd_xl_base_1.0", v)
		}
	})

	t.Run("a list with a model_name but no filename is not flagged as a1111", func(t *testing.T) {
		body := `[{"title":"some entry","model_name":"thing"}]`
		if res := runImageGenModule(t, a1111, 200, body); len(res.Findings) > 0 {
			t.Errorf("a partial entry should not match automatic1111, got %d findings", len(res.Findings))
		}
	})

	t.Run("a generic titled list is not flagged as a1111", func(t *testing.T) {
		body := `[{"title":"My Blog Post","filename":"post.md","author":"someone"}]`
		if res := runImageGenModule(t, a1111, 200, body); len(res.Findings) > 0 {
			t.Errorf("a generic list should not match automatic1111, got %d findings", len(res.Findings))
		}
	})

	t.Run("a model_name and filename without a title is not flagged as a1111", func(t *testing.T) {
		body := `[{"model_name":"thing","filename":"/tmp/thing.bin"}]`
		if res := runImageGenModule(t, a1111, 200, body); len(res.Findings) > 0 {
			t.Errorf("a titleless entry should not match automatic1111, got %d findings", len(res.Findings))
		}
	})

	t.Run("a fooocus-api all-models is flagged with its checkpoint", func(t *testing.T) {
		res := runImageGenModule(t, fooocus, 200, fooocusModels)
		if len(res.Findings) == 0 {
			t.Fatal("expected a fooocus finding")
		}
		if v := imageGenExtract(res, "fooocus_model"); v != "juggernautXL_v8.safetensors" {
			t.Errorf("fooocus_model=%q, want juggernautXL_v8.safetensors", v)
		}
	})

	t.Run("a body without model_filenames is not flagged as fooocus", func(t *testing.T) {
		if res := runImageGenModule(t, fooocus, 200, `{"lora_filenames":["x.safetensors"]}`); len(res.Findings) > 0 {
			t.Errorf("a body without model_filenames should not match fooocus, got %d findings", len(res.Findings))
		}
	})

	t.Run("a body without lora_filenames is not flagged as fooocus", func(t *testing.T) {
		if res := runImageGenModule(t, fooocus, 200, `{"model_filenames":["x.safetensors"]}`); len(res.Findings) > 0 {
			t.Errorf("a body without lora_filenames should not match fooocus, got %d findings", len(res.Findings))
		}
	})

	t.Run("an iopaint server-config is flagged with its file-manager state", func(t *testing.T) {
		res := runImageGenModule(t, iopaint, 200, iopaintConfig)
		if len(res.Findings) == 0 {
			t.Fatal("expected an iopaint finding")
		}
		if v := imageGenExtract(res, "iopaint_file_manager"); v != "true" {
			t.Errorf("iopaint_file_manager=%q, want true", v)
		}
	})

	t.Run("a config without interactiveSegModel is not flagged as iopaint", func(t *testing.T) {
		body := `{"modelInfos":[],"enableFileManager":true,"disableModelSwitch":false,"samplers":[]}`
		if res := runImageGenModule(t, iopaint, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without interactiveSegModel should not match iopaint, got %d findings", len(res.Findings))
		}
	})

	t.Run("a config without enableFileManager is not flagged as iopaint", func(t *testing.T) {
		body := `{"interactiveSegModel":"vit_b","disableModelSwitch":false,"samplers":[]}`
		if res := runImageGenModule(t, iopaint, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without enableFileManager should not match iopaint, got %d findings", len(res.Findings))
		}
	})

	t.Run("a config without disableModelSwitch is not flagged as iopaint", func(t *testing.T) {
		body := `{"interactiveSegModel":"vit_b","enableFileManager":true,"samplers":[]}`
		if res := runImageGenModule(t, iopaint, 200, body); len(res.Findings) > 0 {
			t.Errorf("a body without disableModelSwitch should not match iopaint, got %d findings", len(res.Findings))
		}
	})

	t.Run("a plain 200 body is not a leak", func(t *testing.T) {
		for _, file := range []string{comfyui, a1111, fooocus, iopaint} {
			if res := runImageGenModule(t, file, 200, "ok"); len(res.Findings) > 0 {
				t.Errorf("%s: a plain 200 body should not match, got %d findings", file, len(res.Findings))
			}
		}
	})

	t.Run("a 404 is not a leak", func(t *testing.T) {
		for _, file := range []string{comfyui, a1111, fooocus, iopaint} {
			if res := runImageGenModule(t, file, 404, "not found"); len(res.Findings) > 0 {
				t.Errorf("%s: a 404 should not match, got %d findings", file, len(res.Findings))
			}
		}
	})
}
