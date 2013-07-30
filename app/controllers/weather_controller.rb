class WeatherController < ApplicationController


	def index
		time = Time.zone.now.hour
		logger.info "hello"
		doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/past-24-hour-psi-readings'))
		array = doc2.css('td').to_a
		
		@data = array

		case time
		
		when 0
			@answer = array[378].content.strip
			@previous = array[415].content.strip
		when 1
			@answer = array[379].content.strip
			@previous = array[378].content.strip
		when 2
			@answer = array[380].content.strip
			@previous = array[379].content.strip
		when 3
			@answer = array[381].content.strip
			@previous = array[380].content.strip			
		when 4
			@answer = array[382].content.strip
			@previous = array[381].content.strip			
		when 5
			@answer = array[383].content.strip
			@previous = array[382].content.strip			

		when 6
			@answer = array[384].content.strip
			@previous = array[383].content.strip			

		when 7
			@answer = array[385].content.strip
			@previous = array[384].content.strip			

		when 8
			@answer = array[386].content.strip
			@previous = array[385].content.strip			

		when 9
			@answer = array[387].content.strip
			@previous = array[386].content.strip			

		when 10
			@answer = array[388].content.strip
			@previous = array[387].content.strip			

		when 11
			@answer = array[389].content.strip
			@previous = array[388].content.strip			

		when 12
			@answer = array[404].content.strip
			@previous = array[389].content.strip			

		when 13
			@answer = array[405].content.strip
			@previous = array[404].content.strip			

		when 14
			@answer = array[406].content.strip
			@previous = array[405].content.strip			

		when 15
			@answer = array[407].content.strip
			@previous = array[406].content.strip			

		when 16
			@answer = array[408].content.strip
			@previous = array[407].content.strip			

		when 17
			@answer = array[409].content.strip
			@previous = array[408].content.strip			

		when 18
			@answer = array[410].content.strip
			@previous = array[409].content.strip	

		when 19
			@answer = array[411].content.strip
			@previous = array[410].content.strip			

		when 20
			@answer = array[412].content.strip
			@previous = array[411].content.strip			

		when 21
			@answer = array[413].content.strip
			@previous = array[412].content.strip			

		when 22
			@answer = array[414].content.strip
			@previous = array[413].content.strip			

		when 23
			@answer = array[415].content.strip
			@previous = array[414].content.strip			
		else
			@answer = ":)"
			@previous = ":)"			
		end

		@status = how_bad(@answer)	
		@status2 = how_bad(@previous)
		@color = background(@answer)

		 @north = count_north(time,array,"10")
		 @north_25 = count_north(time,array,"25")
		 @north_status = how_bad(@north)
		 @north_25_status = how_bad(@north_25)

		@south = count_south(time,array,"10")
		@south_25 = count_south(time,array,"25")
		@south_status = how_bad(@south)
		 @south_25_status = how_bad(@south_25)
		
		@east = count_east(time,array,"10")
		@east_25 = count_east(time,array,"25")
		@east_status = how_bad(@east)
		 @east_25_status = how_bad(@east_25)
		
		@west = count_west(time,array,"10")
		@west_25 = count_west(time,array,"25")
		@west_status = how_bad(@west)
		@west_25_status = how_bad(@west_25)


		@central = count_central(time,array,"10")
		@central_25 = count_central(time,array,"25")
		@central_status = how_bad(@central)
		@central_25_status = how_bad(@central_25)
		
		@overall_psi = count_overall(time,array,"10")
	    @overall_25 = count_overall(time,array,"25")
	
	end

	def count_north(time,array,type)
		if type == "10"
			case time
			
			when 0
				return array[14].content.strip
			when 1
				return array[15].content.strip
			when 2
				return array[16].content.strip
			when 3
				return array[17].content.strip
			when 4
				return array[18].content.strip
			when 5
				return array[19].content.strip
			when 6
				return array[20].content.strip
			when 7
				return array[21].content.strip
			when 8
				return array[22].content.strip
			when 9
				return array[23].content.strip
			when 10
				return array[24].content.strip
			when 11
				return array[25].content.strip
			when 12
				return array[105].content.strip
			when 13
				return array[106].content.strip
			when 14
				return array[107].content.strip
			when 15
				return array[108].content.strip
			when 16
				return array[109].content.strip
			when 17
				return array[110].content.strip
			when 18
				return array[111].content.strip
			when 19
				return array[112].content.strip
			when 20
				return array[113].content.strip
			when 21
				return array[114].content.strip
			when 22
				return array[115].content.strip
			when 23
				return array[116].content.strip
			else
				@answer = ":)"
				@previous = ":)"			
			end
		elsif type == "25"
			case time
			
			when 0
				return array[196].content.strip
			when 1
				return array[197].content.strip
			when 2
				return array[198].content.strip
			when 3
				return array[199].content.strip
			when 4
				return array[200].content.strip
			when 5
				return array[201].content.strip
			when 6
				return array[202].content.strip
			when 7
				return array[203].content.strip
			when 8
				return array[204].content.strip
			when 9
				return array[205].content.strip
			when 10
				return array[206].content.strip
			when 11
				return array[207].content.strip
			when 12
				return array[287].content.strip
			when 13
				return array[288].content.strip
			when 14
				return array[289].content.strip
			when 15
				return array[290].content.strip
			when 16
				return array[291].content.strip
			when 17
				return array[292].content.strip
			when 18
				return array[293].content.strip
			when 19
				return array[294].content.strip
			when 20
				return array[295].content.strip
			when 21
				return array[296].content.strip
			when 22
				return array[297].content.strip
			when 23
				return array[298].content.strip
			else
				@answer = ":)"
				@previous = ":)"			
			end
		end
	end


	def count_south(time,array,type)
		if type == "10"
			case time
			
			when 0
				return array[27].content.strip
			when 1
				return array[28].content.strip
			when 2
				return array[29].content.strip
			when 3
				return array[30].content.strip
			when 4
				return array[31].content.strip
			when 5
				return array[32].content.strip
			when 6
				return array[33].content.strip
			when 7
				return array[34].content.strip
			when 8
				return array[35].content.strip
			when 9
				return array[36].content.strip
			when 10
				return array[37].content.strip
			when 11
				return array[38].content.strip
			when 12
				return array[118].content.strip
			when 13
				return array[119].content.strip
			when 14
				return array[120].content.strip
			when 15
				return array[121].content.strip
			when 16
				return array[122].content.strip
			when 17
				return array[123].content.strip
			when 18
				return array[124].content.strip
			when 19
				return array[125].content.strip
			when 20
				return array[126].content.strip
			when 21
				return array[127].content.strip
			when 22
				return array[128].content.strip
			when 23
				return array[129].content.strip
			else
				@answer = ":)"
				@previous = ":)"			
			end
		elsif type == "25"
			case time
			
			when 0
				return array[209].content.strip
			when 1
				return array[210].content.strip
			when 2
				return array[211].content.strip
			when 3
				return array[212].content.strip
			when 4
				return array[213].content.strip
			when 5
				return array[214].content.strip
			when 6
				return array[215].content.strip
			when 7
				return array[216].content.strip
			when 8
				return array[217].content.strip
			when 9
				return array[218].content.strip
			when 10
				return array[219].content.strip
			when 11
				return array[220].content.strip
			when 12
				return array[300].content.strip
			when 13
				return array[301].content.strip
			when 14
				return array[302].content.strip
			when 15
				return array[303].content.strip
			when 16
				return array[304].content.strip
			when 17
				return array[305].content.strip
			when 18
				return array[306].content.strip
			when 19
				return array[307].content.strip
			when 20
				return array[308].content.strip
			when 21
				return array[309].content.strip
			when 22
				return array[310].content.strip
			when 23
				return array[311].content.strip
			else
				@answer = ":)"
				@previous = ":)"			
			end
		end
	end


	def count_east(time,array,type)
		if type == "10"
			case time
			
			when 0
				return array[40].content.strip
			when 1
				return array[41].content.strip
			when 2
				return array[42].content.strip
			when 3
				return array[43].content.strip
			when 4
				return array[44].content.strip
			when 5
				return array[45].content.strip
			when 6
				return array[46].content.strip
			when 7
				return array[47].content.strip
			when 8
				return array[48].content.strip
			when 9
				return array[49].content.strip
			when 10
				return array[50].content.strip
			when 11
				return array[51].content.strip
			when 12
				return array[131].content.strip
			when 13
				return array[132].content.strip
			when 14
				return array[133].content.strip
			when 15
				return array[134].content.strip
			when 16
				return array[135].content.strip
			when 17
				return array[136].content.strip
			when 18
				return array[137].content.strip
			when 19
				return array[138].content.strip
			when 20
				return array[139].content.strip
			when 21
				return array[140].content.strip
			when 22
				return array[141].content.strip
			when 23
				return array[142].content.strip
			else
				@answer = ":)"
				@previous = ":)"			
			end
		elsif type == "25"
			case time

			when 0
				return array[222].content.strip
			when 1
				return array[223].content.strip
			when 2
				return array[224].content.strip
			when 3
				return array[225].content.strip
			when 4
				return array[226].content.strip
			when 5
				return array[227].content.strip
			when 6
				return array[228].content.strip
			when 7
				return array[229].content.strip
			when 8
				return array[230].content.strip
			when 9
				return array[231].content.strip
			when 10
				return array[232].content.strip
			when 11
				return array[233].content.strip
			when 12
				return array[313].content.strip
			when 13
				return array[314].content.strip
			when 14
				return array[315].content.strip
			when 15
				return array[316].content.strip
			when 16
				return array[317].content.strip
			when 17
				return array[318].content.strip
			when 18
				return array[319].content.strip
			when 19
				return array[320].content.strip
			when 20
				return array[321].content.strip
			when 21
				return array[322].content.strip
			when 22
				return array[323].content.strip
			when 23
				return array[324].content.strip
			else
				@answer = ":)"
				@previous = ":)"			
			end
		end
	end


	def count_west(time,array,type)
		if type == "10"
			case time
			
			when 0
				return array[53].content.strip
			when 1
				return array[54].content.strip
			when 2
				return array[55].content.strip
			when 3
				return array[56].content.strip
			when 4
				return array[57].content.strip
			when 5
				return array[58].content.strip
			when 6
				return array[59].content.strip
			when 7
				return array[60].content.strip
			when 8
				return array[61].content.strip
			when 9
				return array[62].content.strip
			when 10
				return array[63].content.strip
			when 11
				return array[64].content.strip
			when 12
				return array[144].content.strip
			when 13
				return array[145].content.strip
			when 14
				return array[146].content.strip
			when 15
				return array[147].content.strip
			when 16
				return array[148].content.strip
			when 17
				return array[149].content.strip
			when 18
				return array[150].content.strip
			when 19
				return array[151].content.strip
			when 20
				return array[152].content.strip
			when 21
				return array[153].content.strip
			when 22
				return array[154].content.strip
			when 23
				return array[155].content.strip
			else
				@answer = ":)"
				@previous = ":)"			
			end
		elsif type == "25"
			case time
			
			when 0
				return array[235].content.strip
			when 1
				return array[236].content.strip
			when 2
				return array[237].content.strip
			when 3
				return array[238].content.strip
			when 4
				return array[239].content.strip
			when 5
				return array[240].content.strip
			when 6
				return array[241].content.strip
			when 7
				return array[242].content.strip
			when 8
				return array[243].content.strip
			when 9
				return array[244].content.strip
			when 10
				return array[245].content.strip
			when 11
				return array[246].content.strip
			when 12
				return array[326].content.strip
			when 13
				return array[327].content.strip
			when 14
				return array[328].content.strip
			when 15
				return array[329].content.strip
			when 16
				return array[330].content.strip
			when 17
				return array[331].content.strip
			when 18
				return array[332].content.strip
			when 19
				return array[333].content.strip
			when 20
				return array[334].content.strip
			when 21
				return array[335].content.strip
			when 22
				return array[336].content.strip
			when 23
				return array[337].content.strip
			else
				@answer = ":)"
				@previous = ":)"			
			end
		end
	end


	def count_central(time,array,type)
		if type == "10"
			case time
			
			when 0
				return array[66].content.strip
			when 1
				return array[67].content.strip
			when 2
				return array[68].content.strip
			when 3
				return array[69].content.strip
			when 4
				return array[70].content.strip
			when 5
				return array[71].content.strip
			when 6
				return array[72].content.strip
			when 7
				return array[73].content.strip
			when 8
				return array[74].content.strip
			when 9
				return array[75].content.strip
			when 10
				return array[76].content.strip
			when 11
				return array[77].content.strip
			when 12
				return array[157].content.strip
			when 13
				return array[158].content.strip
			when 14
				return array[159].content.strip
			when 15
				return array[160].content.strip
			when 16
				return array[161].content.strip
			when 17
				return array[162].content.strip
			when 18
				return array[163].content.strip
			when 19
				return array[164].content.strip
			when 20
				return array[165].content.strip
			when 21
				return array[166].content.strip
			when 22
				return array[167].content.strip
			when 23
				return array[168].content.strip
			else
				@answer = ":)"
				@previous = ":)"			
			end
		elsif type == "25"
			case time
			
			when 0
				return array[248].content.strip
			when 1
				return array[249].content.strip
			when 2
				return array[250].content.strip
			when 3
				return array[251].content.strip
			when 4
				return array[252].content.strip
			when 5
				return array[253].content.strip
			when 6
				return array[254].content.strip
			when 7
				return array[255].content.strip
			when 8
				return array[256].content.strip
			when 9
				return array[257].content.strip
			when 10
				return array[258].content.strip
			when 11
				return array[259].content.strip
			when 12
				return array[339].content.strip
			when 13
				return array[340].content.strip
			when 14
				return array[341].content.strip
			when 15
				return array[342].content.strip
			when 16
				return array[343].content.strip
			when 17
				return array[344].content.strip
			when 18
				return array[345].content.strip
			when 19
				return array[346].content.strip
			when 20
				return array[347].content.strip
			when 21
				return array[348].content.strip
			when 22
				return array[349].content.strip
			when 23
				return array[350].content.strip
			else
				@answer = ":)"
				@previous = ":)"			
			end
		end
	end

	def count_overall(time,array,type)
		if type == "10"
			case time
			
			when 0
				return array[79].content.strip
			when 1
				return array[80].content.strip
			when 2
				return array[81].content.strip
			when 3
				return array[82].content.strip
			when 4
				return array[83].content.strip
			when 5
				return array[84].content.strip
			when 6
				return array[85].content.strip
			when 7
				return array[86].content.strip
			when 8
				return array[87].content.strip
			when 9
				return array[88].content.strip
			when 10
				return array[89].content.strip
			when 11
				return array[90].content.strip
			when 12
				return array[170].content.strip
			when 13
				return array[171].content.strip
			when 14
				return array[172].content.strip
			when 15
				return array[173].content.strip
			when 16
				return array[174].content.strip
			when 17
				return array[175].content.strip
			when 18
				return array[176].content.strip
			when 19
				return array[177].content.strip
			when 20
				return array[178].content.strip
			when 21
				return array[179].content.strip
			when 22
				return array[180].content.strip
			when 23
				return array[181].content.strip
			else
				@answer = ":)"
				@previous = ":)"			
			end
		elsif type == "25"
			case time
			
			when 0
				return array[261].content.strip
			when 1
				return array[262].content.strip
			when 2
				return array[263].content.strip
			when 3
				return array[264].content.strip
			when 4
				return array[265].content.strip
			when 5
				return array[266].content.strip
			when 6
				return array[267].content.strip
			when 7
				return array[268].content.strip
			when 8
				return array[269].content.strip
			when 9
				return array[270].content.strip
			when 10
				return array[271].content.strip
			when 11
				return array[272].content.strip
			when 12
				return array[352].content.strip
			when 13
				return array[353].content.strip
			when 14
				return array[354].content.strip
			when 15
				return array[355].content.strip
			when 16
				return array[356].content.strip
			when 17
				return array[357].content.strip
			when 18
				return array[358].content.strip
			when 19
				return array[359].content.strip
			when 20
				return array[360].content.strip
			when 21
				return array[361].content.strip
			when 22
				return array[362].content.strip
			when 23
				return array[363].content.strip
			else
				@answer = ":)"
				@previous = ":)"			
			end
		end
	end


	def north

		time = Time.zone.now.hour
		type = params[:type]
		doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/past-24-hour-psi-readings'))
		array = doc2.css('td').to_a
		arrayResult = Array.new

		if type == "10"

			arrayResult.push(array[14].content.strip)
			arrayResult.push(array[15].content.strip)
			arrayResult.push(array[16].content.strip)
			arrayResult.push(array[17].content.strip)
			arrayResult.push(array[18].content.strip)
			arrayResult.push(array[19].content.strip)
			arrayResult.push(array[20].content.strip)
			arrayResult.push(array[21].content.strip)
			arrayResult.push(array[22].content.strip)
			arrayResult.push(array[23].content.strip)
			arrayResult.push(array[24].content.strip)
			arrayResult.push(array[25].content.strip)

			arrayResult.push(array[105].content.strip)
			arrayResult.push(array[106].content.strip)
			arrayResult.push(array[107].content.strip)
			arrayResult.push(array[108].content.strip)
			arrayResult.push(array[109].content.strip)
			arrayResult.push(array[110].content.strip)
			arrayResult.push(array[111].content.strip)
			arrayResult.push(array[112].content.strip)
			arrayResult.push(array[113].content.strip)
			arrayResult.push(array[114].content.strip)
			arrayResult.push(array[115].content.strip)
			arrayResult.push(array[116].content.strip)

			render :json => arrayResult			

		elsif type == "25"


			arrayResult.push(array[196].content.strip)
			arrayResult.push(array[197].content.strip)
			arrayResult.push(array[198].content.strip)
			arrayResult.push(array[199].content.strip)
			arrayResult.push(array[200].content.strip)
			arrayResult.push(array[201].content.strip)
			arrayResult.push(array[202].content.strip)
			arrayResult.push(array[203].content.strip)
			arrayResult.push(array[204].content.strip)
			arrayResult.push(array[205].content.strip)
			arrayResult.push(array[206].content.strip)
			arrayResult.push(array[207].content.strip)

			arrayResult.push(array[287].content.strip)
			arrayResult.push(array[288].content.strip)
			arrayResult.push(array[289].content.strip)
			arrayResult.push(array[290].content.strip)
			arrayResult.push(array[291].content.strip)
			arrayResult.push(array[292].content.strip)
			arrayResult.push(array[293].content.strip)
			arrayResult.push(array[294].content.strip)
			arrayResult.push(array[295].content.strip)
			arrayResult.push(array[296].content.strip)
			arrayResult.push(array[297].content.strip)
			arrayResult.push(array[298].content.strip)

			render :json => arrayResult
		end
	end



	def south

		time = Time.zone.now.hour
		type = params[:type]
		doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/past-24-hour-psi-readings'))
		array = doc2.css('td').to_a
		arrayResult = Array.new

		if type == "10"

			arrayResult.push(array[27].content.strip)
			arrayResult.push(array[28].content.strip)
			arrayResult.push(array[29].content.strip)
			arrayResult.push(array[30].content.strip)
			arrayResult.push(array[31].content.strip)
			arrayResult.push(array[32].content.strip)
			arrayResult.push(array[33].content.strip)
			arrayResult.push(array[34].content.strip)
			arrayResult.push(array[35].content.strip)
			arrayResult.push(array[36].content.strip)
			arrayResult.push(array[37].content.strip)
			arrayResult.push(array[38].content.strip)

			arrayResult.push(array[118].content.strip)
			arrayResult.push(array[119].content.strip)
			arrayResult.push(array[120].content.strip)
			arrayResult.push(array[121].content.strip)
			arrayResult.push(array[122].content.strip)
			arrayResult.push(array[123].content.strip)
			arrayResult.push(array[124].content.strip)
			arrayResult.push(array[125].content.strip)
			arrayResult.push(array[126].content.strip)
			arrayResult.push(array[127].content.strip)
			arrayResult.push(array[128].content.strip)
			arrayResult.push(array[129].content.strip)

			render :json => arrayResult

		elsif type == "25"

			arrayResult.push(array[209].content.strip)
			arrayResult.push(array[210].content.strip)
			arrayResult.push(array[211].content.strip)
			arrayResult.push(array[212].content.strip)
			arrayResult.push(array[213].content.strip)
			arrayResult.push(array[214].content.strip)
			arrayResult.push(array[215].content.strip)
			arrayResult.push(array[216].content.strip)
			arrayResult.push(array[217].content.strip)
			arrayResult.push(array[218].content.strip)
			arrayResult.push(array[219].content.strip)
			arrayResult.push(array[220].content.strip)

			arrayResult.push(array[300].content.strip)
			arrayResult.push(array[301].content.strip)
			arrayResult.push(array[302].content.strip)
			arrayResult.push(array[303].content.strip)
			arrayResult.push(array[304].content.strip)
			arrayResult.push(array[305].content.strip)
			arrayResult.push(array[306].content.strip)
			arrayResult.push(array[307].content.strip)
			arrayResult.push(array[308].content.strip)
			arrayResult.push(array[309].content.strip)
			arrayResult.push(array[310].content.strip)
			arrayResult.push(array[311].content.strip)

			render :json => arrayResult
			
		end
	end

	def east

		time = Time.zone.now.hour
		type = params[:type]
		doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/past-24-hour-psi-readings'))
		array = doc2.css('td').to_a
		arrayResult = Array.new

		if type == "10"

			arrayResult.push(array[40].content.strip)
			arrayResult.push(array[41].content.strip)
			arrayResult.push(array[42].content.strip)
			arrayResult.push(array[43].content.strip)
			arrayResult.push(array[44].content.strip)
			arrayResult.push(array[45].content.strip)
			arrayResult.push(array[46].content.strip)
			arrayResult.push(array[47].content.strip)
			arrayResult.push(array[48].content.strip)
			arrayResult.push(array[49].content.strip)
			arrayResult.push(array[50].content.strip)
			arrayResult.push(array[51].content.strip)

			arrayResult.push(array[131].content.strip)
			arrayResult.push(array[132].content.strip)
			arrayResult.push(array[133].content.strip)
			arrayResult.push(array[134].content.strip)
			arrayResult.push(array[135].content.strip)
			arrayResult.push(array[136].content.strip)
			arrayResult.push(array[137].content.strip)
			arrayResult.push(array[138].content.strip)
			arrayResult.push(array[139].content.strip)
			arrayResult.push(array[140].content.strip)
			arrayResult.push(array[141].content.strip)
			arrayResult.push(array[142].content.strip)

			render :json => arrayResult
		
		elsif type == "25"



			arrayResult.push(array[222].content.strip)
			arrayResult.push(array[223].content.strip)
			arrayResult.push(array[224].content.strip)
			arrayResult.push(array[225].content.strip)
			arrayResult.push(array[226].content.strip)
			arrayResult.push(array[227].content.strip)
			arrayResult.push(array[228].content.strip)
			arrayResult.push(array[229].content.strip)
			arrayResult.push(array[230].content.strip)
			arrayResult.push(array[231].content.strip)
			arrayResult.push(array[232].content.strip)
			arrayResult.push(array[233].content.strip)

			arrayResult.push(array[313].content.strip)
			arrayResult.push(array[314].content.strip)
			arrayResult.push(array[315].content.strip)
			arrayResult.push(array[316].content.strip)
			arrayResult.push(array[317].content.strip)
			arrayResult.push(array[318].content.strip)
			arrayResult.push(array[319].content.strip)
			arrayResult.push(array[320].content.strip)
			arrayResult.push(array[321].content.strip)
			arrayResult.push(array[322].content.strip)
			arrayResult.push(array[323].content.strip)
			arrayResult.push(array[324].content.strip)

			render :json => arrayResult

		end
	end

	def west

		time = Time.zone.now.hour
		type = params[:type]
		doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/past-24-hour-psi-readings'))
		array = doc2.css('td').to_a
		arrayResult = Array.new

		if type == "10"
			
			arrayResult.push(array[53].content.strip)
			arrayResult.push(array[54].content.strip)
			arrayResult.push(array[55].content.strip)
			arrayResult.push(array[56].content.strip)
			arrayResult.push(array[57].content.strip)
			arrayResult.push(array[58].content.strip)
			arrayResult.push(array[59].content.strip)
			arrayResult.push(array[60].content.strip)
			arrayResult.push(array[61].content.strip)
			arrayResult.push(array[62].content.strip)
			arrayResult.push(array[63].content.strip)
			arrayResult.push(array[64].content.strip)

			arrayResult.push(array[144].content.strip)
			arrayResult.push(array[145].content.strip)
			arrayResult.push(array[146].content.strip)
			arrayResult.push(array[147].content.strip)
			arrayResult.push(array[148].content.strip)
			arrayResult.push(array[149].content.strip)
			arrayResult.push(array[150].content.strip)
			arrayResult.push(array[151].content.strip)
			arrayResult.push(array[152].content.strip)
			arrayResult.push(array[153].content.strip)
			arrayResult.push(array[154].content.strip)
			arrayResult.push(array[155].content.strip)

			render :json => arrayResult

		elsif type == "25"

			arrayResult.push(array[235].content.strip)
			arrayResult.push(array[236].content.strip)
			arrayResult.push(array[237].content.strip)
			arrayResult.push(array[238].content.strip)
			arrayResult.push(array[239].content.strip)
			arrayResult.push(array[240].content.strip)
			arrayResult.push(array[241].content.strip)
			arrayResult.push(array[242].content.strip)
			arrayResult.push(array[243].content.strip)
			arrayResult.push(array[244].content.strip)
			arrayResult.push(array[245].content.strip)
			arrayResult.push(array[246].content.strip)

			arrayResult.push(array[326].content.strip)
			arrayResult.push(array[327].content.strip)
			arrayResult.push(array[328].content.strip)
			arrayResult.push(array[329].content.strip)
			arrayResult.push(array[330].content.strip)
			arrayResult.push(array[331].content.strip)
			arrayResult.push(array[332].content.strip)
			arrayResult.push(array[333].content.strip)
			arrayResult.push(array[334].content.strip)
			arrayResult.push(array[335].content.strip)
			arrayResult.push(array[336].content.strip)
			arrayResult.push(array[337].content.strip)

			render :json => arrayResult

		end
	end



	def central

		time = Time.zone.now.hour
		type = params[:type]
		doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/past-24-hour-psi-readings'))
		array = doc2.css('td').to_a
		arrayResult = Array.new

		if type == "10"

			arrayResult.push(array[66].content.strip)
			arrayResult.push(array[67].content.strip)
			arrayResult.push(array[68].content.strip)
			arrayResult.push(array[69].content.strip)
			arrayResult.push(array[70].content.strip)
			arrayResult.push(array[71].content.strip)
			arrayResult.push(array[72].content.strip)
			arrayResult.push(array[73].content.strip)
			arrayResult.push(array[74].content.strip)
			arrayResult.push(array[75].content.strip)
			arrayResult.push(array[76].content.strip)
			arrayResult.push(array[77].content.strip)

			arrayResult.push(array[157].content.strip)
			arrayResult.push(array[158].content.strip)
			arrayResult.push(array[159].content.strip)
			arrayResult.push(array[160].content.strip)
			arrayResult.push(array[161].content.strip)
			arrayResult.push(array[162].content.strip)
			arrayResult.push(array[163].content.strip)
			arrayResult.push(array[164].content.strip)
			arrayResult.push(array[165].content.strip)
			arrayResult.push(array[166].content.strip)
			arrayResult.push(array[167].content.strip)
			arrayResult.push(array[168].content.strip)

			render :json => arrayResult

		elsif type == "25"

			arrayResult.push(array[248].content.strip)
			arrayResult.push(array[249].content.strip)
			arrayResult.push(array[250].content.strip)
			arrayResult.push(array[251].content.strip)
			arrayResult.push(array[252].content.strip)
			arrayResult.push(array[253].content.strip)
			arrayResult.push(array[254].content.strip)
			arrayResult.push(array[255].content.strip)
			arrayResult.push(array[256].content.strip)
			arrayResult.push(array[257].content.strip)
			arrayResult.push(array[258].content.strip)
			arrayResult.push(array[259].content.strip)

			arrayResult.push(array[339].content.strip)
			arrayResult.push(array[340].content.strip)
			arrayResult.push(array[341].content.strip)
			arrayResult.push(array[342].content.strip)
			arrayResult.push(array[343].content.strip)
			arrayResult.push(array[344].content.strip)
			arrayResult.push(array[345].content.strip)
			arrayResult.push(array[346].content.strip)
			arrayResult.push(array[347].content.strip)
			arrayResult.push(array[348].content.strip)
			arrayResult.push(array[349].content.strip)
			arrayResult.push(array[350].content.strip)

			render :json => arrayResult
		end
	end


	def overall

		time = Time.zone.now.hour
		type = params[:type]
		doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/past-24-hour-psi-readings'))
		array = doc2.css('td').to_a
		arrayResult = Array.new

		if type == "10"

			arrayResult.push(array[79].content.strip)
			arrayResult.push(array[80].content.strip)
			arrayResult.push(array[81].content.strip)
			arrayResult.push(array[82].content.strip)
			arrayResult.push(array[83].content.strip)
			arrayResult.push(array[84].content.strip)
			arrayResult.push(array[85].content.strip)
			arrayResult.push(array[86].content.strip)
			arrayResult.push(array[87].content.strip)
			arrayResult.push(array[88].content.strip)
			arrayResult.push(array[89].content.strip)
			arrayResult.push(array[90].content.strip)

			arrayResult.push(array[170].content.strip)
			arrayResult.push(array[171].content.strip)
			arrayResult.push(array[172].content.strip)
			arrayResult.push(array[173].content.strip)
			arrayResult.push(array[174].content.strip)
			arrayResult.push(array[175].content.strip)
			arrayResult.push(array[176].content.strip)
			arrayResult.push(array[177].content.strip)
			arrayResult.push(array[178].content.strip)
			arrayResult.push(array[179].content.strip)
			arrayResult.push(array[180].content.strip)
			arrayResult.push(array[181].content.strip)

			render :json => arrayResult

		elsif type == "25"

			arrayResult.push(array[261].content.strip)
			arrayResult.push(array[262].content.strip)
			arrayResult.push(array[263].content.strip)
			arrayResult.push(array[264].content.strip)
			arrayResult.push(array[265].content.strip)
			arrayResult.push(array[266].content.strip)
			arrayResult.push(array[267].content.strip)
			arrayResult.push(array[268].content.strip)
			arrayResult.push(array[269].content.strip)
			arrayResult.push(array[270].content.strip)
			arrayResult.push(array[271].content.strip)
			arrayResult.push(array[272].content.strip)

			arrayResult.push(array[352].content.strip)
			arrayResult.push(array[353].content.strip)
			arrayResult.push(array[354].content.strip)
			arrayResult.push(array[355].content.strip)
			arrayResult.push(array[356].content.strip)
			arrayResult.push(array[357].content.strip)
			arrayResult.push(array[358].content.strip)
			arrayResult.push(array[359].content.strip)
			arrayResult.push(array[360].content.strip)
			arrayResult.push(array[361].content.strip)
			arrayResult.push(array[362].content.strip)
			arrayResult.push(array[363].content.strip)

			render :json => arrayResult
		end
	end




	# def index
	# 	time = Time.zone.now.hour
	# 	logger.info "hello"
	# 	doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/past-24-hour-psi-readings'))
	# 	array = doc2.css('td').to_a
		
	# 	@data = array

	# 	case time
		
	# 	when 0
	# 		@answer = array[32].content.strip
	# 		@previous = array[69].content.strip
	# 	when 1
	# 		@answer = array[33].content.strip
	# 		@previous = array[32].content.strip
	# 	when 2
	# 		@answer = array[34].content.strip
	# 		@previous = array[33].content.strip
	# 	when 3
	# 		@answer = array[35].content.strip
	# 		@previous = array[34].content.strip			
	# 	when 4
	# 		@answer = array[36].content.strip
	# 		@previous = array[35].content.strip			
	# 	when 5
	# 		@answer = array[37].content.strip
	# 		@previous = array[36].content.strip			

	# 	when 6
	# 		@answer = array[38].content.strip
	# 		@previous = array[37].content.strip			

	# 	when 7
	# 		@answer = array[39].content.strip
	# 		@previous = array[38].content.strip			

	# 	when 8
	# 		@answer = array[40].content.strip
	# 		@previous = array[39].content.strip			

	# 	when 9
	# 		@answer = array[41].content.strip
	# 		@previous = array[40].content.strip			

	# 	when 10
	# 		@answer = array[42].content.strip
	# 		@previous = array[41].content.strip			

	# 	when 11
	# 		@answer = array[43].content.strip
	# 		@previous = array[42].content.strip			

	# 	when 12
	# 		@answer = array[58].content.strip
	# 		@previous = array[43].content.strip			

	# 	when 13
	# 		@answer = array[59].content.strip
	# 		@previous = array[58].content.strip			

	# 	when 14
	# 		@answer = array[60].content.strip
	# 		@previous = array[59].content.strip			

	# 	when 15
	# 		@answer = array[61].content.strip
	# 		@previous = array[60].content.strip			

	# 	when 16
	# 		@answer = array[62].content.strip
	# 		@previous = array[61].content.strip			

	# 	when 17
	# 		@answer = array[63].content.strip
	# 		@previous = array[62].content.strip			

	# 	when 18
	# 		@answer = array[64].content.strip
	# 		@previous = array[63].content.strip	

	# 	when 19
	# 		@answer = array[65].content.strip
	# 		@previous = array[64].content.strip			

	# 	when 20
	# 		@answer = array[66].content.strip
	# 		@previous = array[65].content.strip			

	# 	when 21
	# 		@answer = array[67].content.strip
	# 		@previous = array[66].content.strip			

	# 	when 22
	# 		@answer = array[68].content.strip
	# 		@previous = array[67].content.strip			

	# 	when 23
	# 		@answer = array[69].content.strip
	# 		@previous = array[68].content.strip			
	# 	else
	# 		@answer = ":)"
	# 		@previous = ":)"			
	# 	end
	# 	@status = how_bad(@answer)	
	# 	@status2 = how_bad(@previous)
	# 	@color = background(@answer)

	# 	@north = array[1].content.strip
	# 	@north_25 = array[2].content.strip

	# 	@north_status = how_bad(@north)

	# 	@south = array[4].content.strip
	# 	@south_25 = array[5].content.strip

	# 	@south_status = how_bad(@south)
		
	# 	@east = array[7].content.strip
	# 	@east_25 = array[8].content.strip

	# 	@east_status = how_bad(@east)
		
	# 	@west = array[10].content.strip
	# 	@west_25 = array[11].content.strip

	# 	@west_status = how_bad(@west)
		
	# 	@overall_psi = array[16].content.strip

	# 	@overall_25 = array[17].content.strip
	
	# end

	
	#deprecated
	def today

		time = Time.zone.now.hour
		logger.info "hello"
		doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/past-24-hour-psi-readings'))
		array = doc2.css('td').to_a

		arrayResult = Array.new
		arrayResult.push(array[32].content.strip)
		arrayResult.push(array[33].content.strip)
		arrayResult.push(array[34].content.strip)
		arrayResult.push(array[35].content.strip)
		arrayResult.push(array[36].content.strip)
		arrayResult.push(array[37].content.strip)
		arrayResult.push(array[38].content.strip)
		arrayResult.push(array[39].content.strip)
		arrayResult.push(array[40].content.strip)
		arrayResult.push(array[41].content.strip)
		arrayResult.push(array[42].content.strip)
		arrayResult.push(array[43].content.strip)
		arrayResult.push(array[58].content.strip)

		arrayResult.push(array[59].content.strip)
		arrayResult.push(array[60].content.strip)
		arrayResult.push(array[61].content.strip)
		arrayResult.push(array[62].content.strip)
		arrayResult.push(array[63].content.strip)
		arrayResult.push(array[64].content.strip)
		arrayResult.push(array[65].content.strip)
		arrayResult.push(array[66].content.strip)
		arrayResult.push(array[67].content.strip)
		arrayResult.push(array[68].content.strip)
		arrayResult.push(array[69].content.strip)
		
		render :json => arrayResult
	end



	def three
		time = Time.zone.now.hour
		doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/past-24-hour-psi-readings'))
		array = doc2.css('td').to_a

		arrayResult = Array.new
		arrayResult.push(array[378].content.strip)
		arrayResult.push(array[379].content.strip)
		arrayResult.push(array[380].content.strip)
		arrayResult.push(array[381].content.strip)
		arrayResult.push(array[382].content.strip)
		arrayResult.push(array[383].content.strip)
		arrayResult.push(array[384].content.strip)
		arrayResult.push(array[385].content.strip)
		arrayResult.push(array[386].content.strip)
		arrayResult.push(array[387].content.strip)
		arrayResult.push(array[388].content.strip)
		arrayResult.push(array[389].content.strip)

		arrayResult.push(array[404].content.strip)
		arrayResult.push(array[405].content.strip)
		arrayResult.push(array[406].content.strip)
		arrayResult.push(array[407].content.strip)
		arrayResult.push(array[408].content.strip)
		arrayResult.push(array[409].content.strip)
		arrayResult.push(array[410].content.strip)
		arrayResult.push(array[411].content.strip)
		arrayResult.push(array[412].content.strip)
		arrayResult.push(array[413].content.strip)
		arrayResult.push(array[414].content.strip)
		arrayResult.push(array[415].content.strip)

		render :json => arrayResult
	end

	#3 hr psi
	# def three
	# 	time = Time.zone.now.hour
	# 	logger.info "hello"
	# 	doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/past-24-hour-psi-readings'))
	# 	array = doc2.css('td').to_a

	# 	arrayResult = Array.new
	# 	arrayResult.push(array[32].content.strip)
	# 	arrayResult.push(array[33].content.strip)
	# 	arrayResult.push(array[34].content.strip)
	# 	arrayResult.push(array[35].content.strip)
	# 	arrayResult.push(array[36].content.strip)
	# 	arrayResult.push(array[37].content.strip)
	# 	arrayResult.push(array[38].content.strip)
	# 	arrayResult.push(array[39].content.strip)
	# 	arrayResult.push(array[40].content.strip)
	# 	arrayResult.push(array[41].content.strip)
	# 	arrayResult.push(array[42].content.strip)
	# 	arrayResult.push(array[43].content.strip)
	# 	arrayResult.push(array[58].content.strip)

	# 	arrayResult.push(array[59].content.strip)
	# 	arrayResult.push(array[60].content.strip)
	# 	arrayResult.push(array[61].content.strip)
	# 	arrayResult.push(array[62].content.strip)
	# 	arrayResult.push(array[63].content.strip)
	# 	arrayResult.push(array[64].content.strip)
	# 	arrayResult.push(array[65].content.strip)
	# 	arrayResult.push(array[66].content.strip)
	# 	arrayResult.push(array[67].content.strip)
	# 	arrayResult.push(array[68].content.strip)
	# 	arrayResult.push(array[69].content.strip)
		
	# 	render :json => arrayResult
	# end

	#North South East West, 3hr or 2.5
	def nsewc
		if params["type"] == "three"
			time = Time.zone.now.hour
			doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/past-24-hour-psi-readings'))
			array = doc2.css('td').to_a
			arrayResult = Array.new
			arrayResult.push(array[1].content.strip)
			arrayResult.push(array[4].content.strip)
			arrayResult.push(array[7].content.strip)
			arrayResult.push(array[10].content.strip)
			arrayResult.push(array[13].content.strip)

			render :json => arrayResult
		elsif params["type"] == "twofive"
			time = Time.zone.now.hour
			doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/past-24-hour-psi-readings'))
			array = doc2.css('td').to_a
			arrayResult = Array.new
			arrayResult.push(array[2].content.strip)
			arrayResult.push(array[5].content.strip)
			arrayResult.push(array[8].content.strip)
			arrayResult.push(array[11].content.strip)
			arrayResult.push(array[14].content.strip)
			render :json => arrayResult
		else
			time = Time.zone.now.hour
			doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/past-24-hour-psi-readings'))
			array = doc2.css('td').to_a
			arrayResult = Array.new
			arrayResult.push(array[2].content.strip)
			arrayResult.push(array[5].content.strip)
			arrayResult.push(array[8].content.strip)
			arrayResult.push(array[11].content.strip)
			arrayResult.push(array[14].content.strip)
			render :json => arrayResult
		end
	end

	def twofive

		time = Time.now.hour
		logger.info "hello"
		doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/past-24-hour-psi-readings'))
		array = doc2.css('td').to_a

		arrayResult = Array.new
		arrayResult.push(array[32].content.strip)
		arrayResult.push(array[33].content.strip)
		arrayResult.push(array[34].content.strip)
		arrayResult.push(array[35].content.strip)
		arrayResult.push(array[36].content.strip)
		arrayResult.push(array[37].content.strip)
		arrayResult.push(array[38].content.strip)
		arrayResult.push(array[39].content.strip)
		arrayResult.push(array[40].content.strip)
		arrayResult.push(array[41].content.strip)
		arrayResult.push(array[42].content.strip)
		arrayResult.push(array[43].content.strip)
		arrayResult.push(array[58].content.strip)

		arrayResult.push(array[59].content.strip)
		arrayResult.push(array[60].content.strip)
		arrayResult.push(array[61].content.strip)
		arrayResult.push(array[62].content.strip)
		arrayResult.push(array[63].content.strip)
		arrayResult.push(array[64].content.strip)
		arrayResult.push(array[65].content.strip)
		arrayResult.push(array[66].content.strip)
		arrayResult.push(array[67].content.strip)
		arrayResult.push(array[68].content.strip)
		arrayResult.push(array[69].content.strip)
		
		render :json => arrayResult
	end




	def how_bad(psi)

		if psi == "-"
			return ""
		else
			psi = Integer(psi)

			if psi > 0 and psi < 50
				return "Good"
			elsif psi > 50 and psi < 100
				return "Not Good"
			elsif psi > 100 and psi < 200
				return "Unhealthy"
			elsif psi > 200 and psi < 300
				return "Very Unhealthy"
			elsif psi > 300 and psi < 400 
				return "Hazardous"
			elsif psi > 400 and psi < 500
				return "Very Hazardous"
			elsif psi > 500 
				return "Oh My God"
			else
				return "Unconfirmed"
			end

		end
		
	end


	def background(psi)

		if psi == "-"
			return "#95a5a6"
		else
			psi = Integer(psi)
			if psi > 0 and psi < 50
				return "#2ecc71"
			elsif psi > 50 and psi < 100
				return "#f1c40f"
			elsif psi > 100 and psi < 200
				return "#d35400"
			elsif psi > 200 and psi < 300
				return "#e74c3c"
			elsif psi > 300 and psi < 400 
				return "#C0392B"
			elsif psi > 400 and psi < 500
				return "#2c3e50"
			elsif psi > 500 
				return "black"
			else
				return "Unconfirmed"
			end
		end
	end


	#old endpoint
	# def today

	# 	time = Time.now.hour
	# 	logger.info "hello"
	# 	doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/psi-and-pm2-5-readings'))
	# 	array = doc2.css('td').to_a

	# 	arrayResult = Array.new
	# 	arrayResult.push(array[14].content.strip)
	# 	arrayResult.push(array[15].content.strip)
	# 	arrayResult.push(array[16].content.strip)
	# 	arrayResult.push(array[17].content.strip)
	# 	arrayResult.push(array[18].content.strip)
	# 	arrayResult.push(array[19].content.strip)
	# 	arrayResult.push(array[20].content.strip)
	# 	arrayResult.push(array[21].content.strip)
	# 	arrayResult.push(array[22].content.strip)
	# 	arrayResult.push(array[23].content.strip)
	# 	arrayResult.push(array[24].content.strip)
	# 	arrayResult.push(array[25].content.strip)
	# 	arrayResult.push(array[40].content.strip)

	# 	arrayResult.push(array[41].content.strip)
	# 	arrayResult.push(array[42].content.strip)
	# 	arrayResult.push(array[43].content.strip)
	# 	arrayResult.push(array[44].content.strip)
	# 	arrayResult.push(array[45].content.strip)
	# 	arrayResult.push(array[46].content.strip)
	# 	arrayResult.push(array[47].content.strip)
	# 	arrayResult.push(array[48].content.strip)
	# 	arrayResult.push(array[49].content.strip)
	# 	arrayResult.push(array[50].content.strip)
	# 	arrayResult.push(array[51].content.strip)
		
	# 	render :json => arrayResult
	# end


	# old endpoint
	# def index
	# 	time = Time.zone.now.hour
	# 	logger.info "hello"
	# 	doc2 = Nokogiri::HTML(open('http://app2.nea.gov.sg/anti-pollution-radiation-protection/air-pollution/psi/psi-and-pm2-5-readings'))
	# 	array = doc2.css('td').to_a
		
	# 	@data = array

	# 	case time
		
	# 	when 0
	# 		@answer = array[14].content.strip
	# 		@previous = array[51].content.strip
	# 	when 1
	# 		@answer = array[15].content.strip
	# 		@previous = array[14].content.strip
	# 	when 2
	# 		@answer = array[16].content.strip
	# 		@previous = array[15].content.strip
	# 	when 3
	# 		@answer = array[17].content.strip
	# 		@previous = array[16].content.strip			
	# 	when 4
	# 		@answer = array[18].content.strip
	# 		@previous = array[17].content.strip			
	# 	when 5
	# 		@answer = array[19].content.strip
	# 		@previous = array[18].content.strip			

	# 	when 6
	# 		@answer = array[20].content.strip
	# 		@previous = array[19].content.strip			

	# 	when 7
	# 		@answer = array[21].content.strip
	# 		@previous = array[20].content.strip			

	# 	when 8
	# 		@answer = array[22].content.strip
	# 		@previous = array[21].content.strip			

	# 	when 9
	# 		@answer = array[23].content.strip
	# 		@previous = array[22].content.strip			

	# 	when 10
	# 		@answer = array[24].content.strip
	# 		@previous = array[23].content.strip			

	# 	when 11
	# 		@answer = array[25].content.strip
	# 		@previous = array[24].content.strip			

	# 	when 12
	# 		@answer = array[40].content.strip
	# 		@previous = array[25].content.strip			

	# 	when 13
	# 		@answer = array[41].content.strip
	# 		@previous = array[40].content.strip			

	# 	when 14
	# 		@answer = array[42].content.strip
	# 		@previous = array[41].content.strip			

	# 	when 15
	# 		@answer = array[43].content.strip
	# 		@previous = array[42].content.strip			

	# 	when 16
	# 		@answer = array[44].content.strip
	# 		@previous = array[43].content.strip			

	# 	when 17
	# 		@answer = array[45].content.strip
	# 		@previous = array[44].content.strip			

	# 	when 18
	# 		@answer = array[46].content.strip
	# 		@previous = array[45].content.strip	

	# 	when 19
	# 		@answer = array[47].content.strip
	# 		@previous = array[46].content.strip			

	# 	when 20
	# 		@answer = array[48].content.strip
	# 		@previous = array[47].content.strip			

	# 	when 21
	# 		@answer = array[49].content.strip
	# 		@previous = array[48].content.strip			

	# 	when 22
	# 		@answer = array[50].content.strip
	# 		@previous = array[49].content.strip			

	# 	when 23
	# 		@answer = array[51].content.strip
	# 		@previous = array[50].content.strip			
	# 	else
	# 		@answer = ":)"
	# 		@previous = ":)"			
	# 	end
	# 	@status = how_bad(@answer)	
	# 	@status2 = how_bad(@previous)
	# 	@color = background(@answer)	
	
	# end


end
