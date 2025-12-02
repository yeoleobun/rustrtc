package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/pion/webrtc/v3"
	"github.com/pion/webrtc/v3/pkg/media"
)

var (
	mode = flag.String("mode", "client", "Mode: client or server")
	addr = flag.String("addr", "127.0.0.1:3000", "Address to listen on or connect to")
)

type OfferRequest struct {
	Sdp  string `json:"sdp"`
	Type string `json:"type"`
}

type OfferResponse struct {
	Sdp  string `json:"sdp"`
	Type string `json:"type"`
}

func main() {
	flag.Parse()

	if *mode == "server" {
		runServer()
	} else {
		runClient()
	}
}

func runServer() {
	http.HandleFunc("/offer", func(w http.ResponseWriter, r *http.Request) {
		var req OfferRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Handle DataChannel
		pc.OnDataChannel(func(d *webrtc.DataChannel) {
			log.Printf("New DataChannel %s %d\n", d.Label(), d.ID())
			d.OnOpen(func() {
				log.Printf("DataChannel %s open\n", d.Label())
			})
			d.OnMessage(func(msg webrtc.DataChannelMessage) {
				log.Printf("Message from DataChannel '%s': '%s'\n", d.Label(), string(msg.Data))
				// Echo
				d.Send(msg.Data)
			})
		})

		// Handle Track
		pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
			log.Printf("Track has started, of type %d: %s \n", track.PayloadType(), track.Codec().MimeType)
			buf := make([]byte, 1500)
			for {
				_, _, err := track.Read(buf)
				if err != nil {
					return
				}
			}
		})

		// Set Remote Description
		if err := pc.SetRemoteDescription(webrtc.SessionDescription{
			Type: webrtc.SDPTypeOffer,
			SDP:  req.Sdp,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Create Answer
		answer, err := pc.CreateAnswer(nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Gather Candidates
		gatherComplete := webrtc.GatheringCompletePromise(pc)
		if err := pc.SetLocalDescription(answer); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		<-gatherComplete

		resp := OfferResponse{
			Sdp:  pc.LocalDescription().SDP,
			Type: "answer",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	log.Printf("Listening on %s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func runClient() {
	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		log.Fatal(err)
	}

	// Create DataChannel
	dc, err := pc.CreateDataChannel("data", nil)
	if err != nil {
		log.Fatal(err)
	}

	dc.OnOpen(func() {
		log.Printf("DataChannel %s open\n", dc.Label())
		ticker := time.NewTicker(time.Second)
		count := 0
		for range ticker.C {
			count++
			if count > 5 {
				log.Println("SUCCESS: Client finished")
				os.Exit(0)
			}
			msg := fmt.Sprintf("Ping from Pion %s", time.Now().Format(time.RFC3339))
			log.Printf("Sending '%s'\n", msg)
			if err := dc.SendText(msg); err != nil {
				log.Println("Send error:", err)
				return
			}
		}
	})

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		log.Printf("Received '%s'\n", string(msg.Data))
	})

	// Create Video Track
	videoTrack, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8}, "video", "pion")
	if err != nil {
		log.Fatal(err)
	}
	if _, err = pc.AddTrack(videoTrack); err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			time.Sleep(time.Millisecond * 33)
			// Send dummy video packet
			if err := videoTrack.WriteSample(media.Sample{Data: []byte{0x00, 0x00, 0x00, 0x00}, Duration: time.Millisecond * 33}); err != nil {
				return
			}
		}
	}()

	// Create Offer
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		log.Fatal(err)
	}

	gatherComplete := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		log.Fatal(err)
	}
	<-gatherComplete

	// Send Offer
	req := OfferRequest{
		Sdp:  pc.LocalDescription().SDP,
		Type: "offer",
	}
	body, _ := json.Marshal(req)

	resp, err := http.Post("http://"+*addr+"/offer", "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	var answerResp OfferResponse
	if err := json.NewDecoder(resp.Body).Decode(&answerResp); err != nil {
		log.Fatal(err)
	}

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  answerResp.Sdp,
	}); err != nil {
		log.Fatal(err)
	}

	select {}
}
