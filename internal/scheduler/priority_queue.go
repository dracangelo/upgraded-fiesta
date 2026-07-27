package scheduler

import (
	"container/heap"
	"sync"

	"enumscan/internal/models"
)

const (
	PriorityHigh   = 3
	PriorityNormal = 2
	PriorityLow    = 1
)

type PriorityItem struct {
	Event    models.Event
	Priority int
	index    int
}

type itemHeap []*PriorityItem

func (h itemHeap) Len() int           { return len(h) }
func (h itemHeap) Less(i, j int) bool { return h[i].Priority > h[j].Priority } // Highest priority first
func (h itemHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *itemHeap) Push(x any) {
	n := len(*h)
	item := x.(*PriorityItem)
	item.index = n
	*h = append(*h, item)
}
func (h *itemHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*h = old[0 : n-1]
	return item
}

type PriorityQueue struct {
	mu sync.Mutex
	h  itemHeap
}

func NewPriorityQueue() *PriorityQueue {
	pq := &PriorityQueue{h: make(itemHeap, 0)}
	heap.Init(&pq.h)
	return pq
}

func (pq *PriorityQueue) Push(evt models.Event, priority int) {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	heap.Push(&pq.h, &PriorityItem{Event: evt, Priority: priority})
}

func (pq *PriorityQueue) Pop() (models.Event, bool) {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	if len(pq.h) == 0 {
		return models.Event{}, false
	}
	item := heap.Pop(&pq.h).(*PriorityItem)
	return item.Event, true
}

func (pq *PriorityQueue) Len() int {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return len(pq.h)
}
