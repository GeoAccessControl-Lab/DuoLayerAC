package main

import (
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type encoderMetadata struct {
	Format       string     `json:"format"`
	Protocol     string     `json:"protocol"`
	FeatureNames []string   `json:"feature_names"`
	Categories   [][]string `json:"categories"`
	Offsets      []int      `json:"offsets"`
	InputDim     int        `json:"input_dim"`
}

type layerMetadata struct {
	WeightFile string `json:"weight_file"`
	BiasFile   string `json:"bias_file"`
	Out        int    `json:"out_features"`
	In         int    `json:"in_features"`
	Activation string `json:"activation"`
}

type modelMetadata struct {
	Format            string          `json:"format"`
	Model             string          `json:"model"`
	BaseConfigID      string          `json:"base_config_id"`
	CheckpointIndex   int             `json:"checkpoint_index"`
	CheckpointSeed    int             `json:"checkpoint_seed"`
	Protocol          string          `json:"protocol"`
	InputDim          int             `json:"input_dim"`
	DecisionThreshold float64         `json:"decision_threshold"`
	Layers            []layerMetadata `json:"layers"`
}

type sampleRequest struct {
	Features map[string]string          `json:"features"`
	Label    int                        `json:"label"`
	Expected map[string]expectedOutcome `json:"expected"`
}

type expectedOutcome struct {
	Logit       float64 `json:"logit"`
	Probability float64 `json:"probability"`
	Threshold   float64 `json:"threshold"`
	Decision    int     `json:"decision"`
}

type layer struct {
	meta   layerMetadata
	weight []float32
	bias   []float32
}

type detector struct {
	encoder     encoderMetadata
	categoryMap []map[string]int
	model       modelMetadata
	layers      []layer
}

type stats struct {
	Mean float64
	Std  float64
	Min  float64
	P50  float64
	P95  float64
	Max  float64
}

func mustReadJSON(path string, target any) {
	content, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Errorf("read %s: %w", path, err))
	}
	if err := json.Unmarshal(content, target); err != nil {
		panic(fmt.Errorf("parse %s: %w", path, err))
	}
}

func readFloat32LE(path string, expected int) []float32 {
	content, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Errorf("read %s: %w", path, err))
	}
	if len(content) != expected*4 {
		panic(fmt.Errorf("%s: got %d bytes, expected %d", path, len(content), expected*4))
	}
	values := make([]float32, expected)
	for index := range values {
		bits := binary.LittleEndian.Uint32(content[index*4 : index*4+4])
		values[index] = math.Float32frombits(bits)
	}
	return values
}

func loadDetector(root, modelName string) (*detector, time.Duration) {
	started := time.Now()
	var encoder encoderMetadata
	mustReadJSON(filepath.Join(root, "encoder.json"), &encoder)
	modelDir := filepath.Join(root, strings.ToLower(modelName))
	var metadata modelMetadata
	mustReadJSON(filepath.Join(modelDir, "model.json"), &metadata)
	if !strings.EqualFold(metadata.Model, modelName) {
		panic(fmt.Errorf("model metadata is %q, requested %q", metadata.Model, modelName))
	}
	if encoder.InputDim != metadata.InputDim || encoder.Protocol != metadata.Protocol {
		panic("encoder/model protocol mismatch")
	}
	if len(encoder.FeatureNames) != len(encoder.Categories) || len(encoder.Offsets) != len(encoder.FeatureNames) {
		panic("invalid encoder metadata lengths")
	}
	maps := make([]map[string]int, len(encoder.Categories))
	for featureIndex, values := range encoder.Categories {
		maps[featureIndex] = make(map[string]int, len(values))
		for categoryIndex, value := range values {
			maps[featureIndex][value] = encoder.Offsets[featureIndex] + categoryIndex
		}
	}
	layers := make([]layer, len(metadata.Layers))
	for index, info := range metadata.Layers {
		if info.Out <= 0 || info.In <= 0 {
			panic("invalid layer dimensions")
		}
		layers[index] = layer{
			meta:   info,
			weight: readFloat32LE(filepath.Join(modelDir, info.WeightFile), info.Out*info.In),
			bias:   readFloat32LE(filepath.Join(modelDir, info.BiasFile), info.Out),
		}
	}
	return &detector{encoder: encoder, categoryMap: maps, model: metadata, layers: layers}, time.Since(started)
}

func (d *detector) encode(features map[string]string) []int {
	active := make([]int, 0, len(d.encoder.FeatureNames))
	for featureIndex, featureName := range d.encoder.FeatureNames {
		value, present := features[featureName]
		if !present {
			continue
		}
		if encodedIndex, known := d.categoryMap[featureIndex][value]; known {
			active = append(active, encodedIndex)
		}
	}
	return active
}

func sparseAffine(current layer, active []int) []float32 {
	result := append([]float32(nil), current.bias...)
	for outputIndex := 0; outputIndex < current.meta.Out; outputIndex++ {
		rowOffset := outputIndex * current.meta.In
		value := result[outputIndex]
		for _, inputIndex := range active {
			value += current.weight[rowOffset+inputIndex]
		}
		if current.meta.Activation == "relu" && value < 0 {
			value = 0
		}
		result[outputIndex] = value
	}
	return result
}

func denseAffine(current layer, input []float32) []float32 {
	if len(input) != current.meta.In {
		panic("dense layer input size mismatch")
	}
	result := make([]float32, current.meta.Out)
	for outputIndex := 0; outputIndex < current.meta.Out; outputIndex++ {
		rowOffset := outputIndex * current.meta.In
		value := current.bias[outputIndex]
		for inputIndex, inputValue := range input {
			value += current.weight[rowOffset+inputIndex] * inputValue
		}
		if current.meta.Activation == "relu" && value < 0 {
			value = 0
		}
		result[outputIndex] = value
	}
	return result
}

func (d *detector) infer(active []int) (float64, float64, int) {
	if len(d.layers) == 0 {
		panic("model has no layers")
	}
	values := sparseAffine(d.layers[0], active)
	for index := 1; index < len(d.layers); index++ {
		values = denseAffine(d.layers[index], values)
	}
	if len(values) != 1 {
		panic("final layer must have one output")
	}
	logit := float64(values[0])
	var probability float64
	if logit >= 0 {
		z := math.Exp(-logit)
		probability = 1 / (1 + z)
	} else {
		z := math.Exp(logit)
		probability = z / (1 + z)
	}
	decision := 0
	if probability > d.model.DecisionThreshold {
		decision = 1
	}
	return logit, probability, decision
}

func summarize(values []float64) stats {
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	sum := 0.0
	for _, value := range values {
		sum += value
	}
	mean := sum / float64(len(values))
	variance := 0.0
	for _, value := range values {
		delta := value - mean
		variance += delta * delta
	}
	if len(values) > 1 {
		variance /= float64(len(values) - 1)
	}
	percentile := func(q float64) float64 {
		position := int(math.Ceil(q*float64(len(ordered)))) - 1
		if position < 0 {
			position = 0
		}
		if position >= len(ordered) {
			position = len(ordered) - 1
		}
		return ordered[position]
	}
	return stats{
		Mean: mean,
		Std:  math.Sqrt(variance),
		Min:  ordered[0],
		P50:  percentile(0.50),
		P95:  percentile(0.95),
		Max:  ordered[len(ordered)-1],
	}
}

func printStats(prefix string, value stats) {
	fmt.Printf("%s_MEAN_MS=%.6f\n", prefix, value.Mean)
	fmt.Printf("%s_STD_MS=%.6f\n", prefix, value.Std)
	fmt.Printf("%s_MIN_MS=%.6f\n", prefix, value.Min)
	fmt.Printf("%s_P50_MS=%.6f\n", prefix, value.P50)
	fmt.Printf("%s_P95_MS=%.6f\n", prefix, value.P95)
	fmt.Printf("%s_MAX_MS=%.6f\n", prefix, value.Max)
}

func processCPUTime() time.Duration {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		panic(fmt.Errorf("read process CPU time: %w", err))
	}
	user := time.Duration(usage.Utime.Sec)*time.Second + time.Duration(usage.Utime.Usec)*time.Microsecond
	system := time.Duration(usage.Stime.Sec)*time.Second + time.Duration(usage.Stime.Usec)*time.Microsecond
	return user + system
}

func main() {
	modelRoot := flag.String("model-root", "./rs_detector", "deployment artifact root")
	modelName := flag.String("model", "DNN", "LR or DNN")
	inputPath := flag.String("input", "", "request JSON path; defaults to <model-root>/sample_request.json")
	warmupRuns := flag.Int("warmup-runs", 10, "unmeasured warm-up iterations")
	runs := flag.Int("runs", 100, "measured iterations")
	rate := flag.Float64("rate", 0, "measured request rate per second; zero runs without pacing")
	csvPath := flag.String("csv", "", "optional raw per-request CSV output path")
	readyFile := flag.String("ready-file", "", "optional readiness signal file created after warm-up")
	startFile := flag.String("start-file", "", "optional start signal file awaited after warm-up")
	flag.Parse()
	if *runs <= 0 || *warmupRuns < 0 || *rate < 0 {
		panic("runs must be positive and warmup-runs nonnegative")
	}
	*modelName = strings.ToUpper(*modelName)
	if *modelName != "LR" && *modelName != "DNN" {
		panic("model must be LR or DNN")
	}
	if *inputPath == "" {
		*inputPath = filepath.Join(*modelRoot, "sample_request.json")
	}

	runtime.GOMAXPROCS(1)
	d, loadDuration := loadDetector(*modelRoot, *modelName)
	var request sampleRequest
	mustReadJSON(*inputPath, &request)

	runOnce := func() (time.Duration, time.Duration, time.Duration, float64, int) {
		started := time.Now()
		encodeStarted := time.Now()
		active := d.encode(request.Features)
		encodeDuration := time.Since(encodeStarted)
		inferStarted := time.Now()
		_, probability, decision := d.infer(active)
		inferDuration := time.Since(inferStarted)
		return encodeDuration, inferDuration, time.Since(started), probability, decision
	}

	for index := 0; index < *warmupRuns; index++ {
		runOnce()
	}
	if *readyFile != "" {
		if err := os.WriteFile(*readyFile, []byte("ready\n"), 0o644); err != nil {
			panic(fmt.Errorf("create readiness file: %w", err))
		}
	}
	if *startFile != "" {
		for {
			if _, err := os.Stat(*startFile); err == nil {
				break
			} else if !os.IsNotExist(err) {
				panic(fmt.Errorf("wait for start file: %w", err))
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	encodeValues := make([]float64, 0, *runs)
	inferValues := make([]float64, 0, *runs)
	totalValues := make([]float64, 0, *runs)
	probabilityValues := make([]float64, 0, *runs)
	decisionValues := make([]int, 0, *runs)
	probability := 0.0
	decision := 0
	batchStarted := time.Now()
	batchCPUStarted := processCPUTime()
	for index := 0; index < *runs; index++ {
		if *rate > 0 {
			scheduled := batchStarted.Add(time.Duration(float64(index) / *rate * float64(time.Second)))
			if wait := time.Until(scheduled); wait > 0 {
				time.Sleep(wait)
			}
		}
		encodeDuration, inferDuration, totalDuration, currentProbability, currentDecision := runOnce()
		encodeValues = append(encodeValues, float64(encodeDuration.Nanoseconds())/1e6)
		inferValues = append(inferValues, float64(inferDuration.Nanoseconds())/1e6)
		totalValues = append(totalValues, float64(totalDuration.Nanoseconds())/1e6)
		probabilityValues = append(probabilityValues, currentProbability)
		decisionValues = append(decisionValues, currentDecision)
		probability = currentProbability
		decision = currentDecision
	}
	batchCPU := processCPUTime() - batchCPUStarted
	batchWall := time.Since(batchStarted)

	expected, present := request.Expected[*modelName]
	if !present {
		panic("sample request has no expected result for selected model")
	}
	absoluteError := math.Abs(probability - expected.Probability)
	if absoluteError > 2e-5 || decision != expected.Decision {
		panic(fmt.Errorf(
			"inference mismatch: probability %.9f expected %.9f, decision %d expected %d",
			probability, expected.Probability, decision, expected.Decision,
		))
	}
	if *csvPath != "" {
		if err := os.MkdirAll(filepath.Dir(*csvPath), 0o755); err != nil {
			panic(fmt.Errorf("create CSV directory: %w", err))
		}
		file, err := os.Create(*csvPath)
		if err != nil {
			panic(fmt.Errorf("create CSV %s: %w", *csvPath, err))
		}
		writer := csv.NewWriter(file)
		if err := writer.Write([]string{"iteration", "model", "feature_encode_ms", "model_inference_ms", "detection_total_ms", "probability", "threshold", "decision"}); err != nil {
			panic(err)
		}
		for index := range totalValues {
			record := []string{
				strconv.Itoa(index + 1),
				*modelName,
				strconv.FormatFloat(encodeValues[index], 'f', 9, 64),
				strconv.FormatFloat(inferValues[index], 'f', 9, 64),
				strconv.FormatFloat(totalValues[index], 'f', 9, 64),
				strconv.FormatFloat(probabilityValues[index], 'f', 12, 64),
				strconv.FormatFloat(d.model.DecisionThreshold, 'f', 12, 64),
				strconv.Itoa(decisionValues[index]),
			}
			if err := writer.Write(record); err != nil {
				panic(err)
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			panic(err)
		}
		if err := file.Close(); err != nil {
			panic(err)
		}
	}

	fmt.Println("================ EXPERIMENT_SUMMARY_BEGIN ================")
	fmt.Println("EXPERIMENT=BFRDetectorInference")
	fmt.Printf("MODEL=%s\n", *modelName)
	fmt.Printf("BASE_CONFIG_ID=%s\n", d.model.BaseConfigID)
	fmt.Printf("CHECKPOINT_INDEX=%d\n", d.model.CheckpointIndex)
	fmt.Printf("CHECKPOINT_SEED=%d\n", d.model.CheckpointSeed)
	fmt.Printf("INPUT_DIM=%d\n", d.model.InputDim)
	fmt.Printf("ACTIVE_FEATURES=%d\n", len(d.encode(request.Features)))
	fmt.Printf("MODEL_LOAD_MS=%.6f\n", float64(loadDuration.Nanoseconds())/1e6)
	fmt.Printf("WARMUP_RUNS=%d\n", *warmupRuns)
	fmt.Printf("NUM_RUNS=%d\n", *runs)
	fmt.Printf("REQUEST_RATE_PER_SECOND=%.6f\n", *rate)
	fmt.Printf("BATCH_WALL_MS=%.6f\n", float64(batchWall.Nanoseconds())/1e6)
	fmt.Printf("MEASURED_PROCESS_CPU_MS=%.6f\n", float64(batchCPU.Nanoseconds())/1e6)
	fmt.Printf("PROCESS_CPU_MS_PER_REQUEST=%.9f\n", float64(batchCPU.Nanoseconds())/1e6/float64(*runs))
	printStats("FEATURE_ENCODE", summarize(encodeValues))
	printStats("MODEL_INFERENCE", summarize(inferValues))
	printStats("DETECTION_TOTAL", summarize(totalValues))
	fmt.Printf("PROBABILITY=%.9f\n", probability)
	fmt.Printf("DECISION_THRESHOLD=%.9f\n", d.model.DecisionThreshold)
	fmt.Printf("DECISION=%d\n", decision)
	fmt.Printf("REFERENCE_ABS_ERROR=%.12f\n", absoluteError)
	fmt.Println("REFERENCE_MATCH=true")
	if *csvPath != "" {
		fmt.Printf("RAW_CSV=%s\n", *csvPath)
	}
	fmt.Println("================= EXPERIMENT_SUMMARY_END =================")
}
