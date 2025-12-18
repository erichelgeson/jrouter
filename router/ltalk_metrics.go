/*
   Copyright 2024 Josh Deprez

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package router

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// jrouter_ltalk_bytes_in_total
	ltalkBytesInCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{Namespace: "jrouter", Subsystem: "ltalk", Name: "bytes_in_total",
			Help: "count of LocalTalk (LLAP) bytes received",
		},
		[]string{"network"},
	)

	// jrouter_ltalk_packets_in_total
	ltalkPacketsInCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{Namespace: "jrouter", Subsystem: "ltalk", Name: "packets_in_total",
			Help: "count of LocalTalk (LLAP) packets received",
		},
		[]string{"network"},
	)

	// jrouter_ltalk_invalid_packets_in_total
	ltalkInvalidPacketsInCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{Namespace: "jrouter", Subsystem: "ltalk", Name: "invalid_packets_in_total",
			Help: "count of invalid LocalTalk packets received",
		},
		[]string{"network"},
	)

	// jrouter_ltalk_bytes_out_total
	ltalkBytesOutCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{Namespace: "jrouter", Subsystem: "ltalk", Name: "bytes_out_total",
			Help: "count of LocalTalk bytes sent",
		},
		[]string{"network"},
	)

	// jrouter_ltalk_packets_out_total
	ltalkPacketsOutCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{Namespace: "jrouter", Subsystem: "ltalk", Name: "packets_out_total",
			Help: "count of LocalTalk packets sent",
		},
		[]string{"network"},
	)

	// jrouter_ltalk_enq_total
	ltalkENQCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{Namespace: "jrouter", Subsystem: "ltalk", Name: "enq_total",
			Help: "count of LocalTalk ENQ packets sent (node acquisition)",
		},
		[]string{"network"},
	)

	// jrouter_ltalk_ack_total
	ltalkACKCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{Namespace: "jrouter", Subsystem: "ltalk", Name: "ack_total",
			Help: "count of LocalTalk ACK packets sent (node acquisition response)",
		},
		[]string{"network"},
	)
)
