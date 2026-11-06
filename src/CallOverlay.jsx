import { useEffect, useRef, useState } from "react";
import { Camera, Mic, Phone, PhoneOff } from "lucide-react";

export default function CallOverlay({call,incoming,busy,signals,onAccept,onDecline,onEnd,onSignal}){
 const localVideoRef=useRef(null),remoteVideoRef=useRef(null),peerRef=useRef(null),localStreamRef=useRef(null),processedRef=useRef(new Set()),queuedCandidatesRef=useRef([]);
 const [localStream,setLocalStream]=useState(null),[remoteStream,setRemoteStream]=useState(null),[muted,setMuted]=useState(false),[cameraOff,setCameraOff]=useState(false),[mediaError,setMediaError]=useState("");
 useEffect(()=>{
  if(!call||incoming||call.status!=="active")return;
  let cancelled=false,peer;
  async function setup(){
   try{
    if(!navigator.mediaDevices?.getUserMedia)throw new Error("This browser does not support camera and microphone access.");
    const stream=await navigator.mediaDevices.getUserMedia({audio:true,video:call.media_type==="video"});
    if(cancelled){stream.getTracks().forEach(t=>t.stop());return;}
    localStreamRef.current=stream;setLocalStream(stream);
    peer=new RTCPeerConnection({iceServers:[{urls:"stun:stun.l.google.com:19302"},{urls:"stun:stun1.l.google.com:19302"}]});
    peerRef.current=peer;stream.getTracks().forEach(track=>peer.addTrack(track,stream));
    peer.ontrack=event=>{const received=event.streams?.[0];if(received){setRemoteStream(received);if(remoteVideoRef.current)remoteVideoRef.current.srcObject=received;}};
    peer.onicecandidate=event=>{if(event.candidate)onSignal(call.id,"ice-candidate",event.candidate.toJSON()).catch(e=>setMediaError(e.message));};
    peer.onconnectionstatechange=()=>{if(peer.connectionState==="failed")setMediaError("The connection could not be established on this network.");};
    if(call.direction==="outgoing"){const offer=await peer.createOffer();await peer.setLocalDescription(offer);await onSignal(call.id,"offer",peer.localDescription.toJSON());}
   }catch(e){if(!cancelled)setMediaError(e.message||"Camera or microphone access was unavailable.");}
  }
  setup();
  return()=>{cancelled=true;peer?.close();peerRef.current=null;localStreamRef.current?.getTracks().forEach(t=>t.stop());localStreamRef.current=null;setLocalStream(null);setRemoteStream(null);};
 },[call?.id,call?.status,call?.direction,call?.media_type,incoming,onSignal]);
 useEffect(()=>{
  const peer=peerRef.current;if(!peer||!call||call.status!=="active")return;
  const pending=signals.filter(item=>item.call_id===call.id&&!processedRef.current.has(item));pending.forEach(item=>processedRef.current.add(item));
  (async()=>{for(const item of pending){try{
   if(item.signal_type==="offer"){await peer.setRemoteDescription(new RTCSessionDescription(item.signal));while(queuedCandidatesRef.current.length)await peer.addIceCandidate(new RTCIceCandidate(queuedCandidatesRef.current.shift()));const answer=await peer.createAnswer();await peer.setLocalDescription(answer);await onSignal(call.id,"answer",peer.localDescription.toJSON());}
   else if(item.signal_type==="answer"){await peer.setRemoteDescription(new RTCSessionDescription(item.signal));while(queuedCandidatesRef.current.length)await peer.addIceCandidate(new RTCIceCandidate(queuedCandidatesRef.current.shift()));}
   else if(item.signal_type==="ice-candidate"){if(peer.remoteDescription)await peer.addIceCandidate(new RTCIceCandidate(item.signal));else queuedCandidatesRef.current.push(item.signal);}
  }catch(e){setMediaError(e.message||"WebRTC signaling failed.");}}})();
 },[signals,call?.id,call?.status,onSignal]);
 useEffect(()=>{if(localVideoRef.current&&localStream)localVideoRef.current.srcObject=localStream;},[localStream]);
 useEffect(()=>{if(remoteVideoRef.current&&remoteStream)remoteVideoRef.current.srcObject=remoteStream;},[remoteStream]);
 function toggleMute(){const next=!muted;localStreamRef.current?.getAudioTracks().forEach(t=>t.enabled=!next);setMuted(next);}
 function toggleCamera(){const next=!cameraOff;localStreamRef.current?.getVideoTracks().forEach(t=>t.enabled=!next);setCameraOff(next);}
 const active=call?.status==="active"&&!incoming,displayName=incoming?call.caller_username:call.direction==="outgoing"?call.callee_username:call.caller_username;
 return <div className="call-backdrop"><section className={`call-window ${call.media_type==="video"?"video-call":"voice-call"}`}>
  <header className="call-window-header"><div><strong>{incoming?"Incoming call":active?"Call in progress":"Calling…"}</strong><span>{displayName||"TC Chat user"} · {call.media_type==="video"?"Video":"Voice"}</span></div>{!incoming&&<span className="call-live-dot"/>}</header>
  {call.media_type==="video"&&<div className="call-video-stage"><video ref={remoteVideoRef} className="remote-video" autoPlay playsInline/><video ref={localVideoRef} className="local-video" autoPlay playsInline muted/>{!remoteStream&&<div className="call-video-placeholder">Waiting for the other person…</div>}</div>}
  {call.media_type==="audio"&&<div className="voice-call-avatar"><div>{(displayName||"TC").slice(0,2).toUpperCase()}</div><span>{incoming?"Wants to talk":active?"Connected":"Waiting for answer"}</span></div>}
  {mediaError&&<p className="call-error">{mediaError}</p>}
  <footer className="call-controls">{incoming?<><button className="call-control decline" onClick={onDecline} disabled={busy}><PhoneOff size={19}/><span>Decline</span></button><button className="call-control accept" onClick={onAccept} disabled={busy}><Phone size={19}/><span>Accept</span></button></>:<>{active&&<button className={`call-control ${muted?"selected":""}`} onClick={toggleMute}><Mic size={19}/><span>{muted?"Unmute":"Mute"}</span></button>}{active&&call.media_type==="video"&&<button className={`call-control ${cameraOff?"selected":""}`} onClick={toggleCamera}><Camera size={19}/><span>{cameraOff?"Camera on":"Camera off"}</span></button>}<button className="call-control decline" onClick={onEnd}><PhoneOff size={19}/><span>End call</span></button></>}</footer>
 </section></div>;
}
