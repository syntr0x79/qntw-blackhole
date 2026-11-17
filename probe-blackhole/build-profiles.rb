#!/usr/bin/env ruby
require 'json'
require 'securerandom'
require 'fileutils'
abort 'usage: build-profiles.rb PROFILES_JSON OUTPUT_DIRECTORY' unless ARGV.size == 2
profiles=JSON.parse(File.read(ARGV[0])); out=ARGV[1]; FileUtils.mkdir_p(out)
abort 'expected six complete profiles' unless profiles.size==6 && profiles.all?{|p|p['hello']['complete'] && p['hello']['ja3_matches']}
nft=[]
profiles.each do |p|
 h=p['hello']; clauses=[]
 chunk=lambda{|offset,bytes| bytes.bytes.each_slice(16).with_index{|part,i| clauses << "@ih,#{(offset+i*16)*8},#{part.size*8} 0x#{part.pack('C*').unpack1('H*')}"}}
 u16=lambda{|n|[n].pack('n')}
 legacy=h['legacy_version'].to_i(16); sid=h['session_id_length']; suites=h['cipher_suites'].pack('n*'); comp=h['compression_methods'].pack('C*')
 prefix=u16.call(suites.bytesize)+suites+[comp.bytesize].pack('C')+comp
 ext=''.b
 h['extension_types'].zip(h['extension_lengths']).each do |type,len|
  data="\0".b*len
  case type
  when 10; vals=h['supported_groups'].pack('n*');data=u16.call(vals.bytesize)+vals
  when 11; vals=h['ec_point_formats'].pack('C*');data=[vals.bytesize].pack('C')+vals
  when 43; vals=h['supported_versions'].pack('n*');data=[vals.bytesize].pack('C')+vals
  end
  abort "extension length mismatch #{p['ja3']} #{type}" unless data.bytesize==len
  offset=44+sid+prefix.bytesize+2+ext.bytesize
  chunk.call(offset,u16.call(type)+u16.call(len))
  chunk.call(offset+4,data) if [10,11,43].include?(type)
  ext << u16.call(type)+u16.call(len)+data
 end
 unless h['extensions_length'].nil?
  abort 'extensions length mismatch' unless ext.bytesize==h['extensions_length']
  prefix << u16.call(ext.bytesize)
 end
 body=u16.call(legacy)+SecureRandom.random_bytes(32)+[sid].pack('C')+SecureRandom.random_bytes(sid)+prefix+ext
 abort 'handshake length mismatch' unless body.bytesize==h['handshake_lengths'][0]
 handshake=[1,(body.bytesize>>16)&255,(body.bytesize>>8)&255,body.bytesize&255].pack('C*')+body
 abort 'record length mismatch' unless handshake.bytesize==h['record_lengths'][0]
 record=[22].pack('C')+u16.call(h['record_versions'][0])+u16.call(handshake.bytesize)+handshake
 chunk.call(0,record.byteslice(0,11));chunk.call(43,[sid].pack('C'));chunk.call(44+sid,prefix)
 ordered=clauses.sort_by{|s|s.match(/@ih,(\d+)/)[1].to_i}
 nft << "# JA3 #{p['ja3']}\n#{ordered.join(' ')} counter name p_#{p['ja3']} jump quarantine"
 File.binwrite("#{out}/#{p['ja3']}.hello",record)
end
File.write("#{out}/profiles.nft",nft.join("\n")+"\n")
File.write("#{out}/counters.nft",profiles.map{|p|"counter p_#{p['ja3']} { }"}.join("\n")+"\n")
puts JSON.generate({profiles:profiles.size,fixtures:6})
