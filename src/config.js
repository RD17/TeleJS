const Config = {
  Log: {
    verbose: false
  },
  App: {
    id: 2496,
    hash: '8da85b0d5bfe62527e5b244c209159c3',
    version: '0.6.1'
  },
  Modes: {
    allow_tmpfs: false,
    animations: true,
    chrome_packed: false,
    debug: false,
    force_desktop: false,
    force_mobile: false,
    http: false,
    ios_standalone: undefined,
    memory_only: false,
    nacl: true,
    packed: false,
    push_api: true,
    ssl: false,
    test: false,
    webcrypto: true
  }
}

Config.Schema = Config.Schema || {}

Config.Schema.MTProto = { 'constructors': [{ 'id': '481674261', 'predicate': 'vector', 'params': [], 'type': 'Vector t' }, { 'id': '85337187', 'predicate': 'resPQ', 'params': [{ 'name': 'nonce', 'type': 'int128' }, { 'name': 'server_nonce', 'type': 'int128' }, { 'name': 'pq', 'type': 'bytes' }, { 'name': 'server_public_key_fingerprints', 'type': 'Vector<long>' }], 'type': 'ResPQ' }, { 'id': '-2083955988', 'predicate': 'p_q_inner_data', 'params': [{ 'name': 'pq', 'type': 'bytes' }, { 'name': 'p', 'type': 'bytes' }, { 'name': 'q', 'type': 'bytes' }, { 'name': 'nonce', 'type': 'int128' }, { 'name': 'server_nonce', 'type': 'int128' }, { 'name': 'new_nonce', 'type': 'int256' }], 'type': 'P_Q_inner_data' }, { 'id': '2043348061', 'predicate': 'server_DH_params_fail', 'params': [{ 'name': 'nonce', 'type': 'int128' }, { 'name': 'server_nonce', 'type': 'int128' }, { 'name': 'new_nonce_hash', 'type': 'int128' }], 'type': 'Server_DH_Params' }, { 'id': '-790100132', 'predicate': 'server_DH_params_ok', 'params': [{ 'name': 'nonce', 'type': 'int128' }, { 'name': 'server_nonce', 'type': 'int128' }, { 'name': 'encrypted_answer', 'type': 'bytes' }], 'type': 'Server_DH_Params' }, { 'id': '-1249309254', 'predicate': 'server_DH_inner_data', 'params': [{ 'name': 'nonce', 'type': 'int128' }, { 'name': 'server_nonce', 'type': 'int128' }, { 'name': 'g', 'type': 'int' }, { 'name': 'dh_prime', 'type': 'bytes' }, { 'name': 'g_a', 'type': 'bytes' }, { 'name': 'server_time', 'type': 'int' }], 'type': 'Server_DH_inner_data' }, { 'id': '1715713620', 'predicate': 'client_DH_inner_data', 'params': [{ 'name': 'nonce', 'type': 'int128' }, { 'name': 'server_nonce', 'type': 'int128' }, { 'name': 'retry_id', 'type': 'long' }, { 'name': 'g_b', 'type': 'bytes' }], 'type': 'Client_DH_Inner_Data' }, { 'id': '1003222836', 'predicate': 'dh_gen_ok', 'params': [{ 'name': 'nonce', 'type': 'int128' }, { 'name': 'server_nonce', 'type': 'int128' }, { 'name': 'new_nonce_hash1', 'type': 'int128' }], 'type': 'Set_client_DH_params_answer' }, { 'id': '1188831161', 'predicate': 'dh_gen_retry', 'params': [{ 'name': 'nonce', 'type': 'int128' }, { 'name': 'server_nonce', 'type': 'int128' }, { 'name': 'new_nonce_hash2', 'type': 'int128' }], 'type': 'Set_client_DH_params_answer' }, { 'id': '-1499615742', 'predicate': 'dh_gen_fail', 'params': [{ 'name': 'nonce', 'type': 'int128' }, { 'name': 'server_nonce', 'type': 'int128' }, { 'name': 'new_nonce_hash3', 'type': 'int128' }], 'type': 'Set_client_DH_params_answer' }, { 'id': '-212046591', 'predicate': 'rpc_result', 'params': [{ 'name': 'req_msg_id', 'type': 'long' }, { 'name': 'result', 'type': 'Object' }], 'type': 'RpcResult' }, { 'id': '558156313', 'predicate': 'rpc_error', 'params': [{ 'name': 'error_code', 'type': 'int' }, { 'name': 'error_message', 'type': 'string' }], 'type': 'RpcError' }, { 'id': '1579864942', 'predicate': 'rpc_answer_unknown', 'params': [], 'type': 'RpcDropAnswer' }, { 'id': '-847714938', 'predicate': 'rpc_answer_dropped_running', 'params': [], 'type': 'RpcDropAnswer' }, { 'id': '-1539647305', 'predicate': 'rpc_answer_dropped', 'params': [{ 'name': 'msg_id', 'type': 'long' }, { 'name': 'seq_no', 'type': 'int' }, { 'name': 'bytes', 'type': 'int' }], 'type': 'RpcDropAnswer' }, { 'id': '155834844', 'predicate': 'future_salt', 'params': [{ 'name': 'valid_since', 'type': 'int' }, { 'name': 'valid_until', 'type': 'int' }, { 'name': 'salt', 'type': 'long' }], 'type': 'FutureSalt' }, { 'id': '-1370486635', 'predicate': 'future_salts', 'params': [{ 'name': 'req_msg_id', 'type': 'long' }, { 'name': 'now', 'type': 'int' }, { 'name': 'salts', 'type': 'vector<future_salt>' }], 'type': 'FutureSalts' }, { 'id': '880243653', 'predicate': 'pong', 'params': [{ 'name': 'msg_id', 'type': 'long' }, { 'name': 'ping_id', 'type': 'long' }], 'type': 'Pong' }, { 'id': '-501201412', 'predicate': 'destroy_session_ok', 'params': [{ 'name': 'session_id', 'type': 'long' }], 'type': 'DestroySessionRes' }, { 'id': '1658015945', 'predicate': 'destroy_session_none', 'params': [{ 'name': 'session_id', 'type': 'long' }], 'type': 'DestroySessionRes' }, { 'id': '-1631450872', 'predicate': 'new_session_created', 'params': [{ 'name': 'first_msg_id', 'type': 'long' }, { 'name': 'unique_id', 'type': 'long' }, { 'name': 'server_salt', 'type': 'long' }], 'type': 'NewSession' }, { 'id': '1945237724', 'predicate': 'msg_container', 'params': [{ 'name': 'messages', 'type': 'vector<%Message>' }], 'type': 'MessageContainer' }, { 'id': '1538843921', 'predicate': 'message', 'params': [{ 'name': 'msg_id', 'type': 'long' }, { 'name': 'seqno', 'type': 'int' }, { 'name': 'bytes', 'type': 'int' }, { 'name': 'body', 'type': 'Object' }], 'type': 'Message' }, { 'id': '-530561358', 'predicate': 'msg_copy', 'params': [{ 'name': 'orig_message', 'type': 'Message' }], 'type': 'MessageCopy' }, { 'id': '812830625', 'predicate': 'gzip_packed', 'params': [{ 'name': 'packed_data', 'type': 'bytes' }], 'type': 'Object' }, { 'id': '1658238041', 'predicate': 'msgs_ack', 'params': [{ 'name': 'msg_ids', 'type': 'Vector<long>' }], 'type': 'MsgsAck' }, { 'id': '-1477445615', 'predicate': 'bad_msg_notification', 'params': [{ 'name': 'bad_msg_id', 'type': 'long' }, { 'name': 'bad_msg_seqno', 'type': 'int' }, { 'name': 'error_code', 'type': 'int' }], 'type': 'BadMsgNotification' }, { 'id': '-307542917', 'predicate': 'bad_server_salt', 'params': [{ 'name': 'bad_msg_id', 'type': 'long' }, { 'name': 'bad_msg_seqno', 'type': 'int' }, { 'name': 'error_code', 'type': 'int' }, { 'name': 'new_server_salt', 'type': 'long' }], 'type': 'BadMsgNotification' }, { 'id': '2105940488', 'predicate': 'msg_resend_req', 'params': [{ 'name': 'msg_ids', 'type': 'Vector<long>' }], 'type': 'MsgResendReq' }, { 'id': '-630588590', 'predicate': 'msgs_state_req', 'params': [{ 'name': 'msg_ids', 'type': 'Vector<long>' }], 'type': 'MsgsStateReq' }, { 'id': '81704317', 'predicate': 'msgs_state_info', 'params': [{ 'name': 'req_msg_id', 'type': 'long' }, { 'name': 'info', 'type': 'bytes' }], 'type': 'MsgsStateInfo' }, { 'id': '-1933520591', 'predicate': 'msgs_all_info', 'params': [{ 'name': 'msg_ids', 'type': 'Vector<long>' }, { 'name': 'info', 'type': 'bytes' }], 'type': 'MsgsAllInfo' }, { 'id': '661470918', 'predicate': 'msg_detailed_info', 'params': [{ 'name': 'msg_id', 'type': 'long' }, { 'name': 'answer_msg_id', 'type': 'long' }, { 'name': 'bytes', 'type': 'int' }, { 'name': 'status', 'type': 'int' }], 'type': 'MsgDetailedInfo' }, { 'id': '-2137147681', 'predicate': 'msg_new_detailed_info', 'params': [{ 'name': 'answer_msg_id', 'type': 'long' }, { 'name': 'bytes', 'type': 'int' }, { 'name': 'status', 'type': 'int' }], 'type': 'MsgDetailedInfo' }], 'methods': [{ 'id': '1615239032', 'method': 'req_pq', 'params': [{ 'name': 'nonce', 'type': 'int128' }], 'type': 'ResPQ' }, { 'id': '-686627650', 'method': 'req_DH_params', 'params': [{ 'name': 'nonce', 'type': 'int128' }, { 'name': 'server_nonce', 'type': 'int128' }, { 'name': 'p', 'type': 'bytes' }, { 'name': 'q', 'type': 'bytes' }, { 'name': 'public_key_fingerprint', 'type': 'long' }, { 'name': 'encrypted_data', 'type': 'bytes' }], 'type': 'Server_DH_Params' }, { 'id': '-184262881', 'method': 'set_client_DH_params', 'params': [{ 'name': 'nonce', 'type': 'int128' }, { 'name': 'server_nonce', 'type': 'int128' }, { 'name': 'encrypted_data', 'type': 'bytes' }], 'type': 'Set_client_DH_params_answer' }, { 'id': '1491380032', 'method': 'rpc_drop_answer', 'params': [{ 'name': 'req_msg_id', 'type': 'long' }], 'type': 'RpcDropAnswer' }, { 'id': '-1188971260', 'method': 'get_future_salts', 'params': [{ 'name': 'num', 'type': 'int' }], 'type': 'FutureSalts' }, { 'id': '2059302892', 'method': 'ping', 'params': [{ 'name': 'ping_id', 'type': 'long' }], 'type': 'Pong' }, { 'id': '-213746804', 'method': 'ping_delay_disconnect', 'params': [{ 'name': 'ping_id', 'type': 'long' }, { 'name': 'disconnect_delay', 'type': 'int' }], 'type': 'Pong' }, { 'id': '-414113498', 'method': 'destroy_session', 'params': [{ 'name': 'session_id', 'type': 'long' }], 'type': 'DestroySessionRes' }, { 'id': '-1835453025', 'method': 'http_wait', 'params': [{ 'name': 'max_delay', 'type': 'int' }, { 'name': 'wait_after', 'type': 'int' }, { 'name': 'max_wait', 'type': 'int' }], 'type': 'HttpWait' }] }

// From https://github.com/stephenmathieson/node-tlds/blob/master/index.js
Config.TLD = ['abogado', 'ac', 'academy', 'accountants', 'active', 'actor', 'ad', 'adult', 'ae', 'aero', 'af', 'ag', 'agency', 'ai', 'airforce', 'al', 'allfinanz', 'alsace', 'am', 'amsterdam', 'an', 'android', 'ao', 'apartments', 'aq', 'aquarelle', 'ar', 'archi', 'army', 'arpa', 'as', 'asia', 'associates', 'at', 'attorney', 'au', 'auction', 'audio', 'autos', 'aw', 'ax', 'axa', 'az', 'ba', 'band', 'bank', 'bar', 'barclaycard', 'barclays', 'bargains', 'bayern', 'bb', 'bd', 'be', 'beer', 'berlin', 'best', 'bf', 'bg', 'bh', 'bi', 'bid', 'bike', 'bingo', 'bio', 'biz', 'bj', 'black', 'blackfriday', 'bloomberg', 'blue', 'bm', 'bmw', 'bn', 'bnpparibas', 'bo', 'boo', 'boutique', 'br', 'brussels', 'bs', 'bt', 'budapest', 'build', 'builders', 'business', 'buzz', 'bv', 'bw', 'by', 'bz', 'bzh', 'ca', 'cab', 'cal', 'camera', 'camp', 'cancerresearch', 'canon', 'capetown', 'capital', 'caravan', 'cards', 'care', 'career', 'careers', 'cartier', 'casa', 'cash', 'cat', 'catering', 'cc', 'cd', 'center', 'ceo', 'cern', 'cf', 'cg', 'ch', 'channel', 'chat', 'cheap', 'christmas', 'chrome', 'church', 'ci', 'citic', 'city', 'ck', 'cl', 'claims', 'cleaning', 'click', 'clinic', 'clothing', 'club', 'cm', 'cn', 'co', 'coach', 'codes', 'coffee', 'college', 'cologne', 'com', 'community', 'company', 'computer', 'condos', 'construction', 'consulting', 'contractors', 'cooking', 'cool', 'coop', 'country', 'cr', 'credit', 'creditcard', 'cricket', 'crs', 'cruises', 'cu', 'cuisinella', 'cv', 'cw', 'cx', 'cy', 'cymru', 'cz', 'dabur', 'dad', 'dance', 'dating', 'day', 'dclk', 'de', 'deals', 'degree', 'delivery', 'democrat', 'dental', 'dentist', 'desi', 'design', 'dev', 'diamonds', 'diet', 'digital', 'direct', 'directory', 'discount', 'dj', 'dk', 'dm', 'dnp', 'do', 'docs', 'domains', 'doosan', 'durban', 'dvag', 'dz', 'eat', 'ec', 'edu', 'education', 'ee', 'eg', 'email', 'emerck', 'energy', 'engineer', 'engineering', 'enterprises', 'equipment', 'er', 'es', 'esq', 'estate', 'et', 'eu', 'eurovision', 'eus', 'events', 'everbank', 'exchange', 'expert', 'exposed', 'fail', 'farm', 'fashion', 'feedback', 'fi', 'finance', 'financial', 'firmdale', 'fish', 'fishing', 'fit', 'fitness', 'fj', 'fk', 'flights', 'florist', 'flowers', 'flsmidth', 'fly', 'fm', 'fo', 'foo', 'forsale', 'foundation', 'fr', 'frl', 'frogans', 'fund', 'furniture', 'futbol', 'ga', 'gal', 'gallery', 'garden', 'gb', 'gbiz', 'gd', 'ge', 'gent', 'gf', 'gg', 'ggee', 'gh', 'gi', 'gift', 'gifts', 'gives', 'gl', 'glass', 'gle', 'global', 'globo', 'gm', 'gmail', 'gmo', 'gmx', 'gn', 'goog', 'google', 'gop', 'gov', 'gp', 'gq', 'gr', 'graphics', 'gratis', 'green', 'gripe', 'gs', 'gt', 'gu', 'guide', 'guitars', 'guru', 'gw', 'gy', 'hamburg', 'hangout', 'haus', 'healthcare', 'help', 'here', 'hermes', 'hiphop', 'hiv', 'hk', 'hm', 'hn', 'holdings', 'holiday', 'homes', 'horse', 'host', 'hosting', 'house', 'how', 'hr', 'ht', 'hu', 'ibm', 'id', 'ie', 'ifm', 'il', 'im', 'immo', 'immobilien', 'in', 'industries', 'info', 'ing', 'ink', 'institute', 'insure', 'int', 'international', 'investments', 'io', 'iq', 'ir', 'irish', 'is', 'it', 'iwc', 'jcb', 'je', 'jetzt', 'jm', 'jo', 'jobs', 'joburg', 'jp', 'juegos', 'kaufen', 'kddi', 'ke', 'kg', 'kh', 'ki', 'kim', 'kitchen', 'kiwi', 'km', 'kn', 'koeln', 'kp', 'kr', 'krd', 'kred', 'kw', 'ky', 'kyoto', 'kz', 'la', 'lacaixa', 'land', 'lat', 'latrobe', 'lawyer', 'lb', 'lc', 'lds', 'lease', 'legal', 'lgbt', 'li', 'lidl', 'life', 'lighting', 'limited', 'limo', 'link', 'lk', 'loans', 'london', 'lotte', 'lotto', 'lr', 'ls', 'lt', 'ltda', 'lu', 'luxe', 'luxury', 'lv', 'ly', 'ma', 'madrid', 'maison', 'management', 'mango', 'market', 'marketing', 'marriott', 'mc', 'md', 'me', 'media', 'meet', 'melbourne', 'meme', 'memorial', 'menu', 'mg', 'mh', 'miami', 'mil', 'mini', 'mk', 'ml', 'mm', 'mn', 'mo', 'mobi', 'moda', 'moe', 'monash', 'money', 'mormon', 'mortgage', 'moscow', 'motorcycles', 'mov', 'mp', 'mq', 'mr', 'ms', 'mt', 'mu', 'museum', 'mv', 'mw', 'mx', 'my', 'mz', 'na', 'nagoya', 'name', 'navy', 'nc', 'ne', 'net', 'network', 'neustar', 'new', 'nexus', 'nf', 'ng', 'ngo', 'nhk', 'ni', 'nico', 'ninja', 'nl', 'no', 'np', 'nr', 'nra', 'nrw', 'ntt', 'nu', 'nyc', 'nz', 'okinawa', 'om', 'one', 'ong', 'onl', 'ooo', 'org', 'organic', 'osaka', 'otsuka', 'ovh', 'pa', 'paris', 'partners', 'parts', 'party', 'pe', 'pf', 'pg', 'ph', 'pharmacy', 'photo', 'photography', 'photos', 'physio', 'pics', 'pictures', 'pink', 'pizza', 'pk', 'pl', 'place', 'plumbing', 'pm', 'pn', 'pohl', 'poker', 'porn', 'post', 'pr', 'praxi', 'press', 'pro', 'prod', 'productions', 'prof', 'properties', 'property', 'ps', 'pt', 'pub', 'pw', 'py', 'qa', 'qpon', 'quebec', 're', 'realtor', 'recipes', 'red', 'rehab', 'reise', 'reisen', 'reit', 'ren', 'rentals', 'repair', 'report', 'republican', 'rest', 'restaurant', 'reviews', 'rich', 'rio', 'rip', 'ro', 'rocks', 'rodeo', 'rs', 'rsvp', 'ru', 'ruhr', 'rw', 'ryukyu', 'sa', 'saarland', 'sale', 'samsung', 'sarl', 'saxo', 'sb', 'sc', 'sca', 'scb', 'schmidt', 'schule', 'schwarz', 'science', 'scot', 'sd', 'se', 'services', 'sew', 'sexy', 'sg', 'sh', 'shiksha', 'shoes', 'shriram', 'si', 'singles', 'sj', 'sk', 'sky', 'sl', 'sm', 'sn', 'so', 'social', 'software', 'sohu', 'solar', 'solutions', 'soy', 'space', 'spiegel', 'sr', 'st', 'style', 'su', 'supplies', 'supply', 'support', 'surf', 'surgery', 'suzuki', 'sv', 'sx', 'sy', 'sydney', 'systems', 'sz', 'taipei', 'tatar', 'tattoo', 'tax', 'tc', 'td', 'technology', 'tel', 'temasek', 'tennis', 'tf', 'tg', 'th', 'tienda', 'tips', 'tires', 'tirol', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'today', 'tokyo', 'tools', 'top', 'toshiba', 'town', 'toys', 'tp', 'tr', 'trade', 'training', 'travel', 'trust', 'tt', 'tui', 'tv', 'tw', 'tz', 'ua', 'ug', 'uk', 'university', 'uno', 'uol', 'us', 'uy', 'uz', 'va', 'vacations', 'vc', 've', 'vegas', 'ventures', 'versicherung', 'vet', 'vg', 'vi', 'viajes', 'video', 'villas', 'vision', 'vlaanderen', 'vn', 'vodka', 'vote', 'voting', 'voto', 'voyage', 'vu', 'wales', 'wang', 'watch', 'webcam', 'website', 'wed', 'wedding', 'wf', 'whoswho', 'wien', 'wiki', 'williamhill', 'wme', 'work', 'works', 'world', 'ws', 'wtc', 'wtf', '佛山', '集团', '在线', '한국', 'ভারত', '八卦', 'موقع', '公益', '公司', '移动', '我爱你', 'москва', 'қаз', 'онлайн', 'сайт', 'срб', '淡马锡', 'орг', '삼성', 'சிங்கப்பூர்', '商标', '商店', '商城', 'дети', 'мкд', '中文网', '中信', '中国', '中國', '谷歌', 'భారత్', 'ලංකා', 'ભારત', 'भारत', '网店', 'संगठन', '网络', 'укр', '香港', '台湾', '台灣', '手机', 'мон', 'الجزائر', 'عمان', 'ایران', 'امارات', 'بازار', 'الاردن', 'بھارت', 'المغرب', 'السعودية', 'مليسيا', 'شبكة', 'გე', '机构', '组织机构', 'ไทย', 'سورية', 'рус', 'рф', 'تونس', 'みんな', 'グーグル', '世界', 'ਭਾਰਤ', '网址', '游戏', 'vermögensberater', 'vermögensberatung', '企业', 'مصر', 'قطر', '广东', 'இலங்கை', 'இந்தியா', '新加坡', 'فلسطين', '政务', 'xxx', 'xyz', 'yachts', 'yandex', 'ye', 'yoga', 'yokohama', 'youtube', 'yt', 'za', 'zip', 'zm', 'zone', 'zuerich', 'zw']

Config.Schema.API = {
  "constructors": [
    {
      "id": "-1132882121",
      "predicate": "boolFalse",
      "params": [],
      "type": "Bool"
    },
    {
      "id": "-1720552011",
      "predicate": "boolTrue",
      "params": [],
      "type": "Bool"
    },
    {
      "id": "-994444869",
      "predicate": "error",
      "params": [
        {
          "name": "code",
          "type": "int"
        },
        {
          "name": "text",
          "type": "string"
        }
      ],
      "type": "Error"
    },
    {
      "id": "1450380236",
      "predicate": "null",
      "params": [],
      "type": "Null"
    },
    {
      "id": "2134579434",
      "predicate": "inputPeerEmpty",
      "params": [],
      "type": "InputPeer"
    },
    {
      "id": "2107670217",
      "predicate": "inputPeerSelf",
      "params": [],
      "type": "InputPeer"
    },
    {
      "id": "396093539",
      "predicate": "inputPeerChat",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        }
      ],
      "type": "InputPeer"
    },
    {
      "id": "-1182234929",
      "predicate": "inputUserEmpty",
      "params": [],
      "type": "InputUser"
    },
    {
      "id": "-138301121",
      "predicate": "inputUserSelf",
      "params": [],
      "type": "InputUser"
    },
    {
      "id": "-208488460",
      "predicate": "inputPhoneContact",
      "params": [
        {
          "name": "client_id",
          "type": "long"
        },
        {
          "name": "phone",
          "type": "string"
        },
        {
          "name": "first_name",
          "type": "string"
        },
        {
          "name": "last_name",
          "type": "string"
        }
      ],
      "type": "InputContact"
    },
    {
      "id": "-181407105",
      "predicate": "inputFile",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "parts",
          "type": "int"
        },
        {
          "name": "name",
          "type": "string"
        },
        {
          "name": "md5_checksum",
          "type": "string"
        }
      ],
      "type": "InputFile"
    },
    {
      "id": "-1771768449",
      "predicate": "inputMediaEmpty",
      "params": [],
      "type": "InputMedia"
    },
    {
      "id": "792191537",
      "predicate": "inputMediaUploadedPhoto",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "file",
          "type": "InputFile"
        },
        {
          "name": "caption",
          "type": "string"
        },
        {
          "name": "stickers",
          "type": "flags.0?Vector<InputDocument>"
        },
        {
          "name": "ttl_seconds",
          "type": "flags.1?int"
        }
      ],
      "type": "InputMedia"
    },
    {
      "id": "-2114308294",
      "predicate": "inputMediaPhoto",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "id",
          "type": "InputPhoto"
        },
        {
          "name": "caption",
          "type": "string"
        },
        {
          "name": "ttl_seconds",
          "type": "flags.0?int"
        }
      ],
      "type": "InputMedia"
    },
    {
      "id": "-104578748",
      "predicate": "inputMediaGeoPoint",
      "params": [
        {
          "name": "geo_point",
          "type": "InputGeoPoint"
        }
      ],
      "type": "InputMedia"
    },
    {
      "id": "-1494984313",
      "predicate": "inputMediaContact",
      "params": [
        {
          "name": "phone_number",
          "type": "string"
        },
        {
          "name": "first_name",
          "type": "string"
        },
        {
          "name": "last_name",
          "type": "string"
        }
      ],
      "type": "InputMedia"
    },
    {
      "id": "480546647",
      "predicate": "inputChatPhotoEmpty",
      "params": [],
      "type": "InputChatPhoto"
    },
    {
      "id": "-1837345356",
      "predicate": "inputChatUploadedPhoto",
      "params": [
        {
          "name": "file",
          "type": "InputFile"
        }
      ],
      "type": "InputChatPhoto"
    },
    {
      "id": "-1991004873",
      "predicate": "inputChatPhoto",
      "params": [
        {
          "name": "id",
          "type": "InputPhoto"
        }
      ],
      "type": "InputChatPhoto"
    },
    {
      "id": "-457104426",
      "predicate": "inputGeoPointEmpty",
      "params": [],
      "type": "InputGeoPoint"
    },
    {
      "id": "-206066487",
      "predicate": "inputGeoPoint",
      "params": [
        {
          "name": "lat",
          "type": "double"
        },
        {
          "name": "long",
          "type": "double"
        }
      ],
      "type": "InputGeoPoint"
    },
    {
      "id": "483901197",
      "predicate": "inputPhotoEmpty",
      "params": [],
      "type": "InputPhoto"
    },
    {
      "id": "-74070332",
      "predicate": "inputPhoto",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        }
      ],
      "type": "InputPhoto"
    },
    {
      "id": "342061462",
      "predicate": "inputFileLocation",
      "params": [
        {
          "name": "volume_id",
          "type": "long"
        },
        {
          "name": "local_id",
          "type": "int"
        },
        {
          "name": "secret",
          "type": "long"
        }
      ],
      "type": "InputFileLocation"
    },
    {
      "id": "1996904104",
      "predicate": "inputAppEvent",
      "params": [
        {
          "name": "time",
          "type": "double"
        },
        {
          "name": "type",
          "type": "string"
        },
        {
          "name": "peer",
          "type": "long"
        },
        {
          "name": "data",
          "type": "string"
        }
      ],
      "type": "InputAppEvent"
    },
    {
      "id": "-1649296275",
      "predicate": "peerUser",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        }
      ],
      "type": "Peer"
    },
    {
      "id": "-1160714821",
      "predicate": "peerChat",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        }
      ],
      "type": "Peer"
    },
    {
      "id": "-1432995067",
      "predicate": "storage.fileUnknown",
      "params": [],
      "type": "storage.FileType"
    },
    {
      "id": "8322574",
      "predicate": "storage.fileJpeg",
      "params": [],
      "type": "storage.FileType"
    },
    {
      "id": "-891180321",
      "predicate": "storage.fileGif",
      "params": [],
      "type": "storage.FileType"
    },
    {
      "id": "172975040",
      "predicate": "storage.filePng",
      "params": [],
      "type": "storage.FileType"
    },
    {
      "id": "1384777335",
      "predicate": "storage.fileMp3",
      "params": [],
      "type": "storage.FileType"
    },
    {
      "id": "1258941372",
      "predicate": "storage.fileMov",
      "params": [],
      "type": "storage.FileType"
    },
    {
      "id": "1086091090",
      "predicate": "storage.filePartial",
      "params": [],
      "type": "storage.FileType"
    },
    {
      "id": "-1278304028",
      "predicate": "storage.fileMp4",
      "params": [],
      "type": "storage.FileType"
    },
    {
      "id": "276907596",
      "predicate": "storage.fileWebp",
      "params": [],
      "type": "storage.FileType"
    },
    {
      "id": "2086234950",
      "predicate": "fileLocationUnavailable",
      "params": [
        {
          "name": "volume_id",
          "type": "long"
        },
        {
          "name": "local_id",
          "type": "int"
        },
        {
          "name": "secret",
          "type": "long"
        }
      ],
      "type": "FileLocation"
    },
    {
      "id": "1406570614",
      "predicate": "fileLocation",
      "params": [
        {
          "name": "dc_id",
          "type": "int"
        },
        {
          "name": "volume_id",
          "type": "long"
        },
        {
          "name": "local_id",
          "type": "int"
        },
        {
          "name": "secret",
          "type": "long"
        }
      ],
      "type": "FileLocation"
    },
    {
      "id": "537022650",
      "predicate": "userEmpty",
      "params": [
        {
          "name": "id",
          "type": "int"
        }
      ],
      "type": "User"
    },
    {
      "id": "1326562017",
      "predicate": "userProfilePhotoEmpty",
      "params": [],
      "type": "UserProfilePhoto"
    },
    {
      "id": "-715532088",
      "predicate": "userProfilePhoto",
      "params": [
        {
          "name": "photo_id",
          "type": "long"
        },
        {
          "name": "photo_small",
          "type": "FileLocation"
        },
        {
          "name": "photo_big",
          "type": "FileLocation"
        }
      ],
      "type": "UserProfilePhoto"
    },
    {
      "id": "164646985",
      "predicate": "userStatusEmpty",
      "params": [],
      "type": "UserStatus"
    },
    {
      "id": "-306628279",
      "predicate": "userStatusOnline",
      "params": [
        {
          "name": "expires",
          "type": "int"
        }
      ],
      "type": "UserStatus"
    },
    {
      "id": "9203775",
      "predicate": "userStatusOffline",
      "params": [
        {
          "name": "was_online",
          "type": "int"
        }
      ],
      "type": "UserStatus"
    },
    {
      "id": "-1683826688",
      "predicate": "chatEmpty",
      "params": [
        {
          "name": "id",
          "type": "int"
        }
      ],
      "type": "Chat"
    },
    {
      "id": "-652419756",
      "predicate": "chat",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "creator",
          "type": "flags.0?true"
        },
        {
          "name": "kicked",
          "type": "flags.1?true"
        },
        {
          "name": "left",
          "type": "flags.2?true"
        },
        {
          "name": "admins_enabled",
          "type": "flags.3?true"
        },
        {
          "name": "admin",
          "type": "flags.4?true"
        },
        {
          "name": "deactivated",
          "type": "flags.5?true"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "photo",
          "type": "ChatPhoto"
        },
        {
          "name": "participants_count",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "version",
          "type": "int"
        },
        {
          "name": "migrated_to",
          "type": "flags.6?InputChannel"
        }
      ],
      "type": "Chat"
    },
    {
      "id": "120753115",
      "predicate": "chatForbidden",
      "params": [
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "title",
          "type": "string"
        }
      ],
      "type": "Chat"
    },
    {
      "id": "771925524",
      "predicate": "chatFull",
      "params": [
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "participants",
          "type": "ChatParticipants"
        },
        {
          "name": "chat_photo",
          "type": "Photo"
        },
        {
          "name": "notify_settings",
          "type": "PeerNotifySettings"
        },
        {
          "name": "exported_invite",
          "type": "ExportedChatInvite"
        },
        {
          "name": "bot_info",
          "type": "Vector<BotInfo>"
        }
      ],
      "type": "ChatFull"
    },
    {
      "id": "-925415106",
      "predicate": "chatParticipant",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "inviter_id",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        }
      ],
      "type": "ChatParticipant"
    },
    {
      "id": "-57668565",
      "predicate": "chatParticipantsForbidden",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "self_participant",
          "type": "flags.0?ChatParticipant"
        }
      ],
      "type": "ChatParticipants"
    },
    {
      "id": "1061556205",
      "predicate": "chatParticipants",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "participants",
          "type": "Vector<ChatParticipant>"
        },
        {
          "name": "version",
          "type": "int"
        }
      ],
      "type": "ChatParticipants"
    },
    {
      "id": "935395612",
      "predicate": "chatPhotoEmpty",
      "params": [],
      "type": "ChatPhoto"
    },
    {
      "id": "1632839530",
      "predicate": "chatPhoto",
      "params": [
        {
          "name": "photo_small",
          "type": "FileLocation"
        },
        {
          "name": "photo_big",
          "type": "FileLocation"
        }
      ],
      "type": "ChatPhoto"
    },
    {
      "id": "-2082087340",
      "predicate": "messageEmpty",
      "params": [
        {
          "name": "id",
          "type": "int"
        }
      ],
      "type": "Message"
    },
    {
      "id": "-1864508399",
      "predicate": "message",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "out",
          "type": "flags.1?true"
        },
        {
          "name": "mentioned",
          "type": "flags.4?true"
        },
        {
          "name": "media_unread",
          "type": "flags.5?true"
        },
        {
          "name": "silent",
          "type": "flags.13?true"
        },
        {
          "name": "post",
          "type": "flags.14?true"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "from_id",
          "type": "flags.8?int"
        },
        {
          "name": "to_id",
          "type": "Peer"
        },
        {
          "name": "fwd_from",
          "type": "flags.2?MessageFwdHeader"
        },
        {
          "name": "via_bot_id",
          "type": "flags.11?int"
        },
        {
          "name": "reply_to_msg_id",
          "type": "flags.3?int"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "message",
          "type": "string"
        },
        {
          "name": "media",
          "type": "flags.9?MessageMedia"
        },
        {
          "name": "reply_markup",
          "type": "flags.6?ReplyMarkup"
        },
        {
          "name": "entities",
          "type": "flags.7?Vector<MessageEntity>"
        },
        {
          "name": "views",
          "type": "flags.10?int"
        },
        {
          "name": "edit_date",
          "type": "flags.15?int"
        },
        {
          "name": "post_author",
          "type": "flags.16?string"
        }
      ],
      "type": "Message"
    },
    {
      "id": "-1642487306",
      "predicate": "messageService",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "out",
          "type": "flags.1?true"
        },
        {
          "name": "mentioned",
          "type": "flags.4?true"
        },
        {
          "name": "media_unread",
          "type": "flags.5?true"
        },
        {
          "name": "silent",
          "type": "flags.13?true"
        },
        {
          "name": "post",
          "type": "flags.14?true"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "from_id",
          "type": "flags.8?int"
        },
        {
          "name": "to_id",
          "type": "Peer"
        },
        {
          "name": "reply_to_msg_id",
          "type": "flags.3?int"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "action",
          "type": "MessageAction"
        }
      ],
      "type": "Message"
    },
    {
      "id": "1038967584",
      "predicate": "messageMediaEmpty",
      "params": [],
      "type": "MessageMedia"
    },
    {
      "id": "-1256047857",
      "predicate": "messageMediaPhoto",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "photo",
          "type": "flags.0?Photo"
        },
        {
          "name": "caption",
          "type": "flags.1?string"
        },
        {
          "name": "ttl_seconds",
          "type": "flags.2?int"
        }
      ],
      "type": "MessageMedia"
    },
    {
      "id": "1457575028",
      "predicate": "messageMediaGeo",
      "params": [
        {
          "name": "geo",
          "type": "GeoPoint"
        }
      ],
      "type": "MessageMedia"
    },
    {
      "id": "1585262393",
      "predicate": "messageMediaContact",
      "params": [
        {
          "name": "phone_number",
          "type": "string"
        },
        {
          "name": "first_name",
          "type": "string"
        },
        {
          "name": "last_name",
          "type": "string"
        },
        {
          "name": "user_id",
          "type": "int"
        }
      ],
      "type": "MessageMedia"
    },
    {
      "id": "-1618676578",
      "predicate": "messageMediaUnsupported",
      "params": [],
      "type": "MessageMedia"
    },
    {
      "id": "-1230047312",
      "predicate": "messageActionEmpty",
      "params": [],
      "type": "MessageAction"
    },
    {
      "id": "-1503425638",
      "predicate": "messageActionChatCreate",
      "params": [
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "users",
          "type": "Vector<int>"
        }
      ],
      "type": "MessageAction"
    },
    {
      "id": "-1247687078",
      "predicate": "messageActionChatEditTitle",
      "params": [
        {
          "name": "title",
          "type": "string"
        }
      ],
      "type": "MessageAction"
    },
    {
      "id": "2144015272",
      "predicate": "messageActionChatEditPhoto",
      "params": [
        {
          "name": "photo",
          "type": "Photo"
        }
      ],
      "type": "MessageAction"
    },
    {
      "id": "-1780220945",
      "predicate": "messageActionChatDeletePhoto",
      "params": [],
      "type": "MessageAction"
    },
    {
      "id": "1217033015",
      "predicate": "messageActionChatAddUser",
      "params": [
        {
          "name": "users",
          "type": "Vector<int>"
        }
      ],
      "type": "MessageAction"
    },
    {
      "id": "-1297179892",
      "predicate": "messageActionChatDeleteUser",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        }
      ],
      "type": "MessageAction"
    },
    {
      "id": "-455150117",
      "predicate": "dialog",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "pinned",
          "type": "flags.2?true"
        },
        {
          "name": "peer",
          "type": "Peer"
        },
        {
          "name": "top_message",
          "type": "int"
        },
        {
          "name": "read_inbox_max_id",
          "type": "int"
        },
        {
          "name": "read_outbox_max_id",
          "type": "int"
        },
        {
          "name": "unread_count",
          "type": "int"
        },
        {
          "name": "unread_mentions_count",
          "type": "int"
        },
        {
          "name": "notify_settings",
          "type": "PeerNotifySettings"
        },
        {
          "name": "pts",
          "type": "flags.0?int"
        },
        {
          "name": "draft",
          "type": "flags.1?DraftMessage"
        }
      ],
      "type": "Dialog"
    },
    {
      "id": "590459437",
      "predicate": "photoEmpty",
      "params": [
        {
          "name": "id",
          "type": "long"
        }
      ],
      "type": "Photo"
    },
    {
      "id": "-1836524247",
      "predicate": "photo",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "has_stickers",
          "type": "flags.0?true"
        },
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "sizes",
          "type": "Vector<PhotoSize>"
        }
      ],
      "type": "Photo"
    },
    {
      "id": "236446268",
      "predicate": "photoSizeEmpty",
      "params": [
        {
          "name": "type",
          "type": "string"
        }
      ],
      "type": "PhotoSize"
    },
    {
      "id": "2009052699",
      "predicate": "photoSize",
      "params": [
        {
          "name": "type",
          "type": "string"
        },
        {
          "name": "location",
          "type": "FileLocation"
        },
        {
          "name": "w",
          "type": "int"
        },
        {
          "name": "h",
          "type": "int"
        },
        {
          "name": "size",
          "type": "int"
        }
      ],
      "type": "PhotoSize"
    },
    {
      "id": "-374917894",
      "predicate": "photoCachedSize",
      "params": [
        {
          "name": "type",
          "type": "string"
        },
        {
          "name": "location",
          "type": "FileLocation"
        },
        {
          "name": "w",
          "type": "int"
        },
        {
          "name": "h",
          "type": "int"
        },
        {
          "name": "bytes",
          "type": "bytes"
        }
      ],
      "type": "PhotoSize"
    },
    {
      "id": "286776671",
      "predicate": "geoPointEmpty",
      "params": [],
      "type": "GeoPoint"
    },
    {
      "id": "541710092",
      "predicate": "geoPoint",
      "params": [
        {
          "name": "long",
          "type": "double"
        },
        {
          "name": "lat",
          "type": "double"
        }
      ],
      "type": "GeoPoint"
    },
    {
      "id": "-2128698738",
      "predicate": "auth.checkedPhone",
      "params": [
        {
          "name": "phone_registered",
          "type": "Bool"
        }
      ],
      "type": "auth.CheckedPhone"
    },
    {
      "id": "1577067778",
      "predicate": "auth.sentCode",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "phone_registered",
          "type": "flags.0?true"
        },
        {
          "name": "type",
          "type": "auth.SentCodeType"
        },
        {
          "name": "phone_code_hash",
          "type": "string"
        },
        {
          "name": "next_type",
          "type": "flags.1?auth.CodeType"
        },
        {
          "name": "timeout",
          "type": "flags.2?int"
        }
      ],
      "type": "auth.SentCode"
    },
    {
      "id": "-855308010",
      "predicate": "auth.authorization",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "tmp_sessions",
          "type": "flags.0?int"
        },
        {
          "name": "user",
          "type": "User"
        }
      ],
      "type": "auth.Authorization"
    },
    {
      "id": "-543777747",
      "predicate": "auth.exportedAuthorization",
      "params": [
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "bytes",
          "type": "bytes"
        }
      ],
      "type": "auth.ExportedAuthorization"
    },
    {
      "id": "-1195615476",
      "predicate": "inputNotifyPeer",
      "params": [
        {
          "name": "peer",
          "type": "InputPeer"
        }
      ],
      "type": "InputNotifyPeer"
    },
    {
      "id": "423314455",
      "predicate": "inputNotifyUsers",
      "params": [],
      "type": "InputNotifyPeer"
    },
    {
      "id": "1251338318",
      "predicate": "inputNotifyChats",
      "params": [],
      "type": "InputNotifyPeer"
    },
    {
      "id": "-1540769658",
      "predicate": "inputNotifyAll",
      "params": [],
      "type": "InputNotifyPeer"
    },
    {
      "id": "949182130",
      "predicate": "inputPeerNotifySettings",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "show_previews",
          "type": "flags.0?true"
        },
        {
          "name": "silent",
          "type": "flags.1?true"
        },
        {
          "name": "mute_until",
          "type": "int"
        },
        {
          "name": "sound",
          "type": "string"
        }
      ],
      "type": "InputPeerNotifySettings"
    },
    {
      "id": "-1378534221",
      "predicate": "peerNotifyEventsEmpty",
      "params": [],
      "type": "PeerNotifyEvents"
    },
    {
      "id": "1830677896",
      "predicate": "peerNotifyEventsAll",
      "params": [],
      "type": "PeerNotifyEvents"
    },
    {
      "id": "1889961234",
      "predicate": "peerNotifySettingsEmpty",
      "params": [],
      "type": "PeerNotifySettings"
    },
    {
      "id": "-1697798976",
      "predicate": "peerNotifySettings",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "show_previews",
          "type": "flags.0?true"
        },
        {
          "name": "silent",
          "type": "flags.1?true"
        },
        {
          "name": "mute_until",
          "type": "int"
        },
        {
          "name": "sound",
          "type": "string"
        }
      ],
      "type": "PeerNotifySettings"
    },
    {
      "id": "-860866985",
      "predicate": "wallPaper",
      "params": [
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "sizes",
          "type": "Vector<PhotoSize>"
        },
        {
          "name": "color",
          "type": "int"
        }
      ],
      "type": "WallPaper"
    },
    {
      "id": "253890367",
      "predicate": "userFull",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "blocked",
          "type": "flags.0?true"
        },
        {
          "name": "phone_calls_available",
          "type": "flags.4?true"
        },
        {
          "name": "phone_calls_private",
          "type": "flags.5?true"
        },
        {
          "name": "user",
          "type": "User"
        },
        {
          "name": "about",
          "type": "flags.1?string"
        },
        {
          "name": "link",
          "type": "contacts.Link"
        },
        {
          "name": "profile_photo",
          "type": "flags.2?Photo"
        },
        {
          "name": "notify_settings",
          "type": "PeerNotifySettings"
        },
        {
          "name": "bot_info",
          "type": "flags.3?BotInfo"
        },
        {
          "name": "common_chats_count",
          "type": "int"
        }
      ],
      "type": "UserFull"
    },
    {
      "id": "-116274796",
      "predicate": "contact",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "mutual",
          "type": "Bool"
        }
      ],
      "type": "Contact"
    },
    {
      "id": "-805141448",
      "predicate": "importedContact",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "client_id",
          "type": "long"
        }
      ],
      "type": "ImportedContact"
    },
    {
      "id": "1444661369",
      "predicate": "contactBlocked",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        }
      ],
      "type": "ContactBlocked"
    },
    {
      "id": "-748155807",
      "predicate": "contactStatus",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "status",
          "type": "UserStatus"
        }
      ],
      "type": "ContactStatus"
    },
    {
      "id": "986597452",
      "predicate": "contacts.link",
      "params": [
        {
          "name": "my_link",
          "type": "ContactLink"
        },
        {
          "name": "foreign_link",
          "type": "ContactLink"
        },
        {
          "name": "user",
          "type": "User"
        }
      ],
      "type": "contacts.Link"
    },
    {
      "id": "-353862078",
      "predicate": "contacts.contacts",
      "params": [
        {
          "name": "contacts",
          "type": "Vector<Contact>"
        },
        {
          "name": "saved_count",
          "type": "int"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "contacts.Contacts"
    },
    {
      "id": "-1219778094",
      "predicate": "contacts.contactsNotModified",
      "params": [],
      "type": "contacts.Contacts"
    },
    {
      "id": "2010127419",
      "predicate": "contacts.importedContacts",
      "params": [
        {
          "name": "imported",
          "type": "Vector<ImportedContact>"
        },
        {
          "name": "popular_invites",
          "type": "Vector<PopularContact>"
        },
        {
          "name": "retry_contacts",
          "type": "Vector<long>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "contacts.ImportedContacts"
    },
    {
      "id": "471043349",
      "predicate": "contacts.blocked",
      "params": [
        {
          "name": "blocked",
          "type": "Vector<ContactBlocked>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "contacts.Blocked"
    },
    {
      "id": "-1878523231",
      "predicate": "contacts.blockedSlice",
      "params": [
        {
          "name": "count",
          "type": "int"
        },
        {
          "name": "blocked",
          "type": "Vector<ContactBlocked>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "contacts.Blocked"
    },
    {
      "id": "446822276",
      "predicate": "contacts.found",
      "params": [
        {
          "name": "results",
          "type": "Vector<Peer>"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "contacts.Found"
    },
    {
      "id": "364538944",
      "predicate": "messages.dialogs",
      "params": [
        {
          "name": "dialogs",
          "type": "Vector<Dialog>"
        },
        {
          "name": "messages",
          "type": "Vector<Message>"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "messages.Dialogs"
    },
    {
      "id": "1910543603",
      "predicate": "messages.dialogsSlice",
      "params": [
        {
          "name": "count",
          "type": "int"
        },
        {
          "name": "dialogs",
          "type": "Vector<Dialog>"
        },
        {
          "name": "messages",
          "type": "Vector<Message>"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "messages.Dialogs"
    },
    {
      "id": "-1938715001",
      "predicate": "messages.messages",
      "params": [
        {
          "name": "messages",
          "type": "Vector<Message>"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "messages.Messages"
    },
    {
      "id": "189033187",
      "predicate": "messages.messagesSlice",
      "params": [
        {
          "name": "count",
          "type": "int"
        },
        {
          "name": "messages",
          "type": "Vector<Message>"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "messages.Messages"
    },
    {
      "id": "1694474197",
      "predicate": "messages.chats",
      "params": [
        {
          "name": "chats",
          "type": "Vector<Chat>"
        }
      ],
      "type": "messages.Chats"
    },
    {
      "id": "-438840932",
      "predicate": "messages.chatFull",
      "params": [
        {
          "name": "full_chat",
          "type": "ChatFull"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "messages.ChatFull"
    },
    {
      "id": "-1269012015",
      "predicate": "messages.affectedHistory",
      "params": [
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        },
        {
          "name": "offset",
          "type": "int"
        }
      ],
      "type": "messages.AffectedHistory"
    },
    {
      "id": "1474492012",
      "predicate": "inputMessagesFilterEmpty",
      "params": [],
      "type": "MessagesFilter"
    },
    {
      "id": "-1777752804",
      "predicate": "inputMessagesFilterPhotos",
      "params": [],
      "type": "MessagesFilter"
    },
    {
      "id": "-1614803355",
      "predicate": "inputMessagesFilterVideo",
      "params": [],
      "type": "MessagesFilter"
    },
    {
      "id": "1458172132",
      "predicate": "inputMessagesFilterPhotoVideo",
      "params": [],
      "type": "MessagesFilter"
    },
    {
      "id": "522914557",
      "predicate": "updateNewMessage",
      "params": [
        {
          "name": "message",
          "type": "Message"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "1318109142",
      "predicate": "updateMessageID",
      "params": [
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "random_id",
          "type": "long"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1576161051",
      "predicate": "updateDeleteMessages",
      "params": [
        {
          "name": "messages",
          "type": "Vector<int>"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "1548249383",
      "predicate": "updateUserTyping",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "action",
          "type": "SendMessageAction"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1704596961",
      "predicate": "updateChatUserTyping",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "action",
          "type": "SendMessageAction"
        }
      ],
      "type": "Update"
    },
    {
      "id": "125178264",
      "predicate": "updateChatParticipants",
      "params": [
        {
          "name": "participants",
          "type": "ChatParticipants"
        }
      ],
      "type": "Update"
    },
    {
      "id": "469489699",
      "predicate": "updateUserStatus",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "status",
          "type": "UserStatus"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1489818765",
      "predicate": "updateUserName",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "first_name",
          "type": "string"
        },
        {
          "name": "last_name",
          "type": "string"
        },
        {
          "name": "username",
          "type": "string"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1791935732",
      "predicate": "updateUserPhoto",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "photo",
          "type": "UserProfilePhoto"
        },
        {
          "name": "previous",
          "type": "Bool"
        }
      ],
      "type": "Update"
    },
    {
      "id": "628472761",
      "predicate": "updateContactRegistered",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1657903163",
      "predicate": "updateContactLink",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "my_link",
          "type": "ContactLink"
        },
        {
          "name": "foreign_link",
          "type": "ContactLink"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1519637954",
      "predicate": "updates.state",
      "params": [
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "qts",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "seq",
          "type": "int"
        },
        {
          "name": "unread_count",
          "type": "int"
        }
      ],
      "type": "updates.State"
    },
    {
      "id": "1567990072",
      "predicate": "updates.differenceEmpty",
      "params": [
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "seq",
          "type": "int"
        }
      ],
      "type": "updates.Difference"
    },
    {
      "id": "16030880",
      "predicate": "updates.difference",
      "params": [
        {
          "name": "new_messages",
          "type": "Vector<Message>"
        },
        {
          "name": "new_encrypted_messages",
          "type": "Vector<EncryptedMessage>"
        },
        {
          "name": "other_updates",
          "type": "Vector<Update>"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        },
        {
          "name": "state",
          "type": "updates.State"
        }
      ],
      "type": "updates.Difference"
    },
    {
      "id": "-1459938943",
      "predicate": "updates.differenceSlice",
      "params": [
        {
          "name": "new_messages",
          "type": "Vector<Message>"
        },
        {
          "name": "new_encrypted_messages",
          "type": "Vector<EncryptedMessage>"
        },
        {
          "name": "other_updates",
          "type": "Vector<Update>"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        },
        {
          "name": "intermediate_state",
          "type": "updates.State"
        }
      ],
      "type": "updates.Difference"
    },
    {
      "id": "-484987010",
      "predicate": "updatesTooLong",
      "params": [],
      "type": "Updates"
    },
    {
      "id": "-1857044719",
      "predicate": "updateShortMessage",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "out",
          "type": "flags.1?true"
        },
        {
          "name": "mentioned",
          "type": "flags.4?true"
        },
        {
          "name": "media_unread",
          "type": "flags.5?true"
        },
        {
          "name": "silent",
          "type": "flags.13?true"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "message",
          "type": "string"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "fwd_from",
          "type": "flags.2?MessageFwdHeader"
        },
        {
          "name": "via_bot_id",
          "type": "flags.11?int"
        },
        {
          "name": "reply_to_msg_id",
          "type": "flags.3?int"
        },
        {
          "name": "entities",
          "type": "flags.7?Vector<MessageEntity>"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "377562760",
      "predicate": "updateShortChatMessage",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "out",
          "type": "flags.1?true"
        },
        {
          "name": "mentioned",
          "type": "flags.4?true"
        },
        {
          "name": "media_unread",
          "type": "flags.5?true"
        },
        {
          "name": "silent",
          "type": "flags.13?true"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "from_id",
          "type": "int"
        },
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "message",
          "type": "string"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "fwd_from",
          "type": "flags.2?MessageFwdHeader"
        },
        {
          "name": "via_bot_id",
          "type": "flags.11?int"
        },
        {
          "name": "reply_to_msg_id",
          "type": "flags.3?int"
        },
        {
          "name": "entities",
          "type": "flags.7?Vector<MessageEntity>"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "2027216577",
      "predicate": "updateShort",
      "params": [
        {
          "name": "update",
          "type": "Update"
        },
        {
          "name": "date",
          "type": "int"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "1918567619",
      "predicate": "updatesCombined",
      "params": [
        {
          "name": "updates",
          "type": "Vector<Update>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "seq_start",
          "type": "int"
        },
        {
          "name": "seq",
          "type": "int"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "1957577280",
      "predicate": "updates",
      "params": [
        {
          "name": "updates",
          "type": "Vector<Update>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "seq",
          "type": "int"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "539045032",
      "predicate": "photos.photo",
      "params": [
        {
          "name": "photo",
          "type": "Photo"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "photos.Photo"
    },
    {
      "id": "157948117",
      "predicate": "upload.file",
      "params": [
        {
          "name": "type",
          "type": "storage.FileType"
        },
        {
          "name": "mtime",
          "type": "int"
        },
        {
          "name": "bytes",
          "type": "bytes"
        }
      ],
      "type": "upload.File"
    },
    {
      "id": "98092748",
      "predicate": "dcOption",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "ipv6",
          "type": "flags.0?true"
        },
        {
          "name": "media_only",
          "type": "flags.1?true"
        },
        {
          "name": "tcpo_only",
          "type": "flags.2?true"
        },
        {
          "name": "cdn",
          "type": "flags.3?true"
        },
        {
          "name": "static",
          "type": "flags.4?true"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "ip_address",
          "type": "string"
        },
        {
          "name": "port",
          "type": "int"
        }
      ],
      "type": "DcOption"
    },
    {
      "id": "-1913424220",
      "predicate": "config",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "phonecalls_enabled",
          "type": "flags.1?true"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "expires",
          "type": "int"
        },
        {
          "name": "test_mode",
          "type": "Bool"
        },
        {
          "name": "this_dc",
          "type": "int"
        },
        {
          "name": "dc_options",
          "type": "Vector<DcOption>"
        },
        {
          "name": "chat_size_max",
          "type": "int"
        },
        {
          "name": "megagroup_size_max",
          "type": "int"
        },
        {
          "name": "forwarded_count_max",
          "type": "int"
        },
        {
          "name": "online_update_period_ms",
          "type": "int"
        },
        {
          "name": "offline_blur_timeout_ms",
          "type": "int"
        },
        {
          "name": "offline_idle_timeout_ms",
          "type": "int"
        },
        {
          "name": "online_cloud_timeout_ms",
          "type": "int"
        },
        {
          "name": "notify_cloud_delay_ms",
          "type": "int"
        },
        {
          "name": "notify_default_delay_ms",
          "type": "int"
        },
        {
          "name": "chat_big_size",
          "type": "int"
        },
        {
          "name": "push_chat_period_ms",
          "type": "int"
        },
        {
          "name": "push_chat_limit",
          "type": "int"
        },
        {
          "name": "saved_gifs_limit",
          "type": "int"
        },
        {
          "name": "edit_time_limit",
          "type": "int"
        },
        {
          "name": "rating_e_decay",
          "type": "int"
        },
        {
          "name": "stickers_recent_limit",
          "type": "int"
        },
        {
          "name": "stickers_faved_limit",
          "type": "int"
        },
        {
          "name": "tmp_sessions",
          "type": "flags.0?int"
        },
        {
          "name": "pinned_dialogs_count_max",
          "type": "int"
        },
        {
          "name": "call_receive_timeout_ms",
          "type": "int"
        },
        {
          "name": "call_ring_timeout_ms",
          "type": "int"
        },
        {
          "name": "call_connect_timeout_ms",
          "type": "int"
        },
        {
          "name": "call_packet_timeout_ms",
          "type": "int"
        },
        {
          "name": "me_url_prefix",
          "type": "string"
        },
        {
          "name": "suggested_lang_code",
          "type": "flags.2?string"
        },
        {
          "name": "lang_pack_version",
          "type": "flags.2?int"
        },
        {
          "name": "disabled_features",
          "type": "Vector<DisabledFeature>"
        }
      ],
      "type": "Config"
    },
    {
      "id": "-1910892683",
      "predicate": "nearestDc",
      "params": [
        {
          "name": "country",
          "type": "string"
        },
        {
          "name": "this_dc",
          "type": "int"
        },
        {
          "name": "nearest_dc",
          "type": "int"
        }
      ],
      "type": "NearestDc"
    },
    {
      "id": "-1987579119",
      "predicate": "help.appUpdate",
      "params": [
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "critical",
          "type": "Bool"
        },
        {
          "name": "url",
          "type": "string"
        },
        {
          "name": "text",
          "type": "string"
        }
      ],
      "type": "help.AppUpdate"
    },
    {
      "id": "-1000708810",
      "predicate": "help.noAppUpdate",
      "params": [],
      "type": "help.AppUpdate"
    },
    {
      "id": "415997816",
      "predicate": "help.inviteText",
      "params": [
        {
          "name": "message",
          "type": "string"
        }
      ],
      "type": "help.InviteText"
    },
    {
      "id": "-265263912",
      "predicate": "inputPeerNotifyEventsEmpty",
      "params": [],
      "type": "InputPeerNotifyEvents"
    },
    {
      "id": "-395694988",
      "predicate": "inputPeerNotifyEventsAll",
      "params": [],
      "type": "InputPeerNotifyEvents"
    },
    {
      "id": "-1916114267",
      "predicate": "photos.photos",
      "params": [
        {
          "name": "photos",
          "type": "Vector<Photo>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "photos.Photos"
    },
    {
      "id": "352657236",
      "predicate": "photos.photosSlice",
      "params": [
        {
          "name": "count",
          "type": "int"
        },
        {
          "name": "photos",
          "type": "Vector<Photo>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "photos.Photos"
    },
    {
      "id": "1662091044",
      "predicate": "wallPaperSolid",
      "params": [
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "bg_color",
          "type": "int"
        },
        {
          "name": "color",
          "type": "int"
        }
      ],
      "type": "WallPaper"
    },
    {
      "id": "314359194",
      "predicate": "updateNewEncryptedMessage",
      "params": [
        {
          "name": "message",
          "type": "EncryptedMessage"
        },
        {
          "name": "qts",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "386986326",
      "predicate": "updateEncryptedChatTyping",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1264392051",
      "predicate": "updateEncryption",
      "params": [
        {
          "name": "chat",
          "type": "EncryptedChat"
        },
        {
          "name": "date",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "956179895",
      "predicate": "updateEncryptedMessagesRead",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "max_date",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1417756512",
      "predicate": "encryptedChatEmpty",
      "params": [
        {
          "name": "id",
          "type": "int"
        }
      ],
      "type": "EncryptedChat"
    },
    {
      "id": "1006044124",
      "predicate": "encryptedChatWaiting",
      "params": [
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "access_hash",
          "type": "long"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "admin_id",
          "type": "int"
        },
        {
          "name": "participant_id",
          "type": "int"
        }
      ],
      "type": "EncryptedChat"
    },
    {
      "id": "-931638658",
      "predicate": "encryptedChatRequested",
      "params": [
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "access_hash",
          "type": "long"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "admin_id",
          "type": "int"
        },
        {
          "name": "participant_id",
          "type": "int"
        },
        {
          "name": "g_a",
          "type": "bytes"
        }
      ],
      "type": "EncryptedChat"
    },
    {
      "id": "-94974410",
      "predicate": "encryptedChat",
      "params": [
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "access_hash",
          "type": "long"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "admin_id",
          "type": "int"
        },
        {
          "name": "participant_id",
          "type": "int"
        },
        {
          "name": "g_a_or_b",
          "type": "bytes"
        },
        {
          "name": "key_fingerprint",
          "type": "long"
        }
      ],
      "type": "EncryptedChat"
    },
    {
      "id": "332848423",
      "predicate": "encryptedChatDiscarded",
      "params": [
        {
          "name": "id",
          "type": "int"
        }
      ],
      "type": "EncryptedChat"
    },
    {
      "id": "-247351839",
      "predicate": "inputEncryptedChat",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "access_hash",
          "type": "long"
        }
      ],
      "type": "InputEncryptedChat"
    },
    {
      "id": "-1038136962",
      "predicate": "encryptedFileEmpty",
      "params": [],
      "type": "EncryptedFile"
    },
    {
      "id": "1248893260",
      "predicate": "encryptedFile",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        },
        {
          "name": "size",
          "type": "int"
        },
        {
          "name": "dc_id",
          "type": "int"
        },
        {
          "name": "key_fingerprint",
          "type": "int"
        }
      ],
      "type": "EncryptedFile"
    },
    {
      "id": "406307684",
      "predicate": "inputEncryptedFileEmpty",
      "params": [],
      "type": "InputEncryptedFile"
    },
    {
      "id": "1690108678",
      "predicate": "inputEncryptedFileUploaded",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "parts",
          "type": "int"
        },
        {
          "name": "md5_checksum",
          "type": "string"
        },
        {
          "name": "key_fingerprint",
          "type": "int"
        }
      ],
      "type": "InputEncryptedFile"
    },
    {
      "id": "1511503333",
      "predicate": "inputEncryptedFile",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        }
      ],
      "type": "InputEncryptedFile"
    },
    {
      "id": "-182231723",
      "predicate": "inputEncryptedFileLocation",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        }
      ],
      "type": "InputFileLocation"
    },
    {
      "id": "-317144808",
      "predicate": "encryptedMessage",
      "params": [
        {
          "name": "random_id",
          "type": "long"
        },
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "bytes",
          "type": "bytes"
        },
        {
          "name": "file",
          "type": "EncryptedFile"
        }
      ],
      "type": "EncryptedMessage"
    },
    {
      "id": "594758406",
      "predicate": "encryptedMessageService",
      "params": [
        {
          "name": "random_id",
          "type": "long"
        },
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "bytes",
          "type": "bytes"
        }
      ],
      "type": "EncryptedMessage"
    },
    {
      "id": "-1058912715",
      "predicate": "messages.dhConfigNotModified",
      "params": [
        {
          "name": "random",
          "type": "bytes"
        }
      ],
      "type": "messages.DhConfig"
    },
    {
      "id": "740433629",
      "predicate": "messages.dhConfig",
      "params": [
        {
          "name": "g",
          "type": "int"
        },
        {
          "name": "p",
          "type": "bytes"
        },
        {
          "name": "version",
          "type": "int"
        },
        {
          "name": "random",
          "type": "bytes"
        }
      ],
      "type": "messages.DhConfig"
    },
    {
      "id": "1443858741",
      "predicate": "messages.sentEncryptedMessage",
      "params": [
        {
          "name": "date",
          "type": "int"
        }
      ],
      "type": "messages.SentEncryptedMessage"
    },
    {
      "id": "-1802240206",
      "predicate": "messages.sentEncryptedFile",
      "params": [
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "file",
          "type": "EncryptedFile"
        }
      ],
      "type": "messages.SentEncryptedMessage"
    },
    {
      "id": "-95482955",
      "predicate": "inputFileBig",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "parts",
          "type": "int"
        },
        {
          "name": "name",
          "type": "string"
        }
      ],
      "type": "InputFile"
    },
    {
      "id": "767652808",
      "predicate": "inputEncryptedFileBigUploaded",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "parts",
          "type": "int"
        },
        {
          "name": "key_fingerprint",
          "type": "int"
        }
      ],
      "type": "InputEncryptedFile"
    },
    {
      "id": "-1373745011",
      "predicate": "storage.filePdf",
      "params": [],
      "type": "storage.FileType"
    },
    {
      "id": "-1629621880",
      "predicate": "inputMessagesFilterDocument",
      "params": [],
      "type": "MessagesFilter"
    },
    {
      "id": "-648121413",
      "predicate": "inputMessagesFilterPhotoVideoDocuments",
      "params": [],
      "type": "MessagesFilter"
    },
    {
      "id": "-364179876",
      "predicate": "updateChatParticipantAdd",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "inviter_id",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "version",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "1851755554",
      "predicate": "updateChatParticipantDelete",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "version",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1906403213",
      "predicate": "updateDcOptions",
      "params": [
        {
          "name": "dc_options",
          "type": "Vector<DcOption>"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-476700163",
      "predicate": "inputMediaUploadedDocument",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "file",
          "type": "InputFile"
        },
        {
          "name": "thumb",
          "type": "flags.2?InputFile"
        },
        {
          "name": "mime_type",
          "type": "string"
        },
        {
          "name": "attributes",
          "type": "Vector<DocumentAttribute>"
        },
        {
          "name": "caption",
          "type": "string"
        },
        {
          "name": "stickers",
          "type": "flags.0?Vector<InputDocument>"
        },
        {
          "name": "ttl_seconds",
          "type": "flags.1?int"
        }
      ],
      "type": "InputMedia"
    },
    {
      "id": "1523279502",
      "predicate": "inputMediaDocument",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "id",
          "type": "InputDocument"
        },
        {
          "name": "caption",
          "type": "string"
        },
        {
          "name": "ttl_seconds",
          "type": "flags.0?int"
        }
      ],
      "type": "InputMedia"
    },
    {
      "id": "2084836563",
      "predicate": "messageMediaDocument",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "document",
          "type": "flags.0?Document"
        },
        {
          "name": "caption",
          "type": "flags.1?string"
        },
        {
          "name": "ttl_seconds",
          "type": "flags.2?int"
        }
      ],
      "type": "MessageMedia"
    },
    {
      "id": "1928391342",
      "predicate": "inputDocumentEmpty",
      "params": [],
      "type": "InputDocument"
    },
    {
      "id": "410618194",
      "predicate": "inputDocument",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        }
      ],
      "type": "InputDocument"
    },
    {
      "id": "1125058340",
      "predicate": "inputDocumentFileLocation",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        },
        {
          "name": "version",
          "type": "int"
        }
      ],
      "type": "InputFileLocation"
    },
    {
      "id": "922273905",
      "predicate": "documentEmpty",
      "params": [
        {
          "name": "id",
          "type": "long"
        }
      ],
      "type": "Document"
    },
    {
      "id": "-2027738169",
      "predicate": "document",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "mime_type",
          "type": "string"
        },
        {
          "name": "size",
          "type": "int"
        },
        {
          "name": "thumb",
          "type": "PhotoSize"
        },
        {
          "name": "dc_id",
          "type": "int"
        },
        {
          "name": "version",
          "type": "int"
        },
        {
          "name": "attributes",
          "type": "Vector<DocumentAttribute>"
        }
      ],
      "type": "Document"
    },
    {
      "id": "398898678",
      "predicate": "help.support",
      "params": [
        {
          "name": "phone_number",
          "type": "string"
        },
        {
          "name": "user",
          "type": "User"
        }
      ],
      "type": "help.Support"
    },
    {
      "id": "1959820384",
      "predicate": "notifyAll",
      "params": [],
      "type": "NotifyPeer"
    },
    {
      "id": "-1073230141",
      "predicate": "notifyChats",
      "params": [],
      "type": "NotifyPeer"
    },
    {
      "id": "-1613493288",
      "predicate": "notifyPeer",
      "params": [
        {
          "name": "peer",
          "type": "Peer"
        }
      ],
      "type": "NotifyPeer"
    },
    {
      "id": "-1261946036",
      "predicate": "notifyUsers",
      "params": [],
      "type": "NotifyPeer"
    },
    {
      "id": "-2131957734",
      "predicate": "updateUserBlocked",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "blocked",
          "type": "Bool"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1094555409",
      "predicate": "updateNotifySettings",
      "params": [
        {
          "name": "peer",
          "type": "NotifyPeer"
        },
        {
          "name": "notify_settings",
          "type": "PeerNotifySettings"
        }
      ],
      "type": "Update"
    },
    {
      "id": "381645902",
      "predicate": "sendMessageTypingAction",
      "params": [],
      "type": "SendMessageAction"
    },
    {
      "id": "-44119819",
      "predicate": "sendMessageCancelAction",
      "params": [],
      "type": "SendMessageAction"
    },
    {
      "id": "-1584933265",
      "predicate": "sendMessageRecordVideoAction",
      "params": [],
      "type": "SendMessageAction"
    },
    {
      "id": "-378127636",
      "predicate": "sendMessageUploadVideoAction",
      "params": [
        {
          "name": "progress",
          "type": "int"
        }
      ],
      "type": "SendMessageAction"
    },
    {
      "id": "-718310409",
      "predicate": "sendMessageRecordAudioAction",
      "params": [],
      "type": "SendMessageAction"
    },
    {
      "id": "-212740181",
      "predicate": "sendMessageUploadAudioAction",
      "params": [
        {
          "name": "progress",
          "type": "int"
        }
      ],
      "type": "SendMessageAction"
    },
    {
      "id": "-774682074",
      "predicate": "sendMessageUploadPhotoAction",
      "params": [
        {
          "name": "progress",
          "type": "int"
        }
      ],
      "type": "SendMessageAction"
    },
    {
      "id": "-1441998364",
      "predicate": "sendMessageUploadDocumentAction",
      "params": [
        {
          "name": "progress",
          "type": "int"
        }
      ],
      "type": "SendMessageAction"
    },
    {
      "id": "393186209",
      "predicate": "sendMessageGeoLocationAction",
      "params": [],
      "type": "SendMessageAction"
    },
    {
      "id": "1653390447",
      "predicate": "sendMessageChooseContactAction",
      "params": [],
      "type": "SendMessageAction"
    },
    {
      "id": "-337352679",
      "predicate": "updateServiceNotification",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "popup",
          "type": "flags.0?true"
        },
        {
          "name": "inbox_date",
          "type": "flags.1?int"
        },
        {
          "name": "type",
          "type": "string"
        },
        {
          "name": "message",
          "type": "string"
        },
        {
          "name": "media",
          "type": "MessageMedia"
        },
        {
          "name": "entities",
          "type": "Vector<MessageEntity>"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-496024847",
      "predicate": "userStatusRecently",
      "params": [],
      "type": "UserStatus"
    },
    {
      "id": "129960444",
      "predicate": "userStatusLastWeek",
      "params": [],
      "type": "UserStatus"
    },
    {
      "id": "2011940674",
      "predicate": "userStatusLastMonth",
      "params": [],
      "type": "UserStatus"
    },
    {
      "id": "-298113238",
      "predicate": "updatePrivacy",
      "params": [
        {
          "name": "key",
          "type": "PrivacyKey"
        },
        {
          "name": "rules",
          "type": "Vector<PrivacyRule>"
        }
      ],
      "type": "Update"
    },
    {
      "id": "1335282456",
      "predicate": "inputPrivacyKeyStatusTimestamp",
      "params": [],
      "type": "InputPrivacyKey"
    },
    {
      "id": "-1137792208",
      "predicate": "privacyKeyStatusTimestamp",
      "params": [],
      "type": "PrivacyKey"
    },
    {
      "id": "218751099",
      "predicate": "inputPrivacyValueAllowContacts",
      "params": [],
      "type": "InputPrivacyRule"
    },
    {
      "id": "407582158",
      "predicate": "inputPrivacyValueAllowAll",
      "params": [],
      "type": "InputPrivacyRule"
    },
    {
      "id": "320652927",
      "predicate": "inputPrivacyValueAllowUsers",
      "params": [
        {
          "name": "users",
          "type": "Vector<InputUser>"
        }
      ],
      "type": "InputPrivacyRule"
    },
    {
      "id": "195371015",
      "predicate": "inputPrivacyValueDisallowContacts",
      "params": [],
      "type": "InputPrivacyRule"
    },
    {
      "id": "-697604407",
      "predicate": "inputPrivacyValueDisallowAll",
      "params": [],
      "type": "InputPrivacyRule"
    },
    {
      "id": "-1877932953",
      "predicate": "inputPrivacyValueDisallowUsers",
      "params": [
        {
          "name": "users",
          "type": "Vector<InputUser>"
        }
      ],
      "type": "InputPrivacyRule"
    },
    {
      "id": "-123988",
      "predicate": "privacyValueAllowContacts",
      "params": [],
      "type": "PrivacyRule"
    },
    {
      "id": "1698855810",
      "predicate": "privacyValueAllowAll",
      "params": [],
      "type": "PrivacyRule"
    },
    {
      "id": "1297858060",
      "predicate": "privacyValueAllowUsers",
      "params": [
        {
          "name": "users",
          "type": "Vector<int>"
        }
      ],
      "type": "PrivacyRule"
    },
    {
      "id": "-125240806",
      "predicate": "privacyValueDisallowContacts",
      "params": [],
      "type": "PrivacyRule"
    },
    {
      "id": "-1955338397",
      "predicate": "privacyValueDisallowAll",
      "params": [],
      "type": "PrivacyRule"
    },
    {
      "id": "209668535",
      "predicate": "privacyValueDisallowUsers",
      "params": [
        {
          "name": "users",
          "type": "Vector<int>"
        }
      ],
      "type": "PrivacyRule"
    },
    {
      "id": "1430961007",
      "predicate": "account.privacyRules",
      "params": [
        {
          "name": "rules",
          "type": "Vector<PrivacyRule>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "account.PrivacyRules"
    },
    {
      "id": "-1194283041",
      "predicate": "accountDaysTTL",
      "params": [
        {
          "name": "days",
          "type": "int"
        }
      ],
      "type": "AccountDaysTTL"
    },
    {
      "id": "314130811",
      "predicate": "updateUserPhone",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "phone",
          "type": "string"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1369215196",
      "predicate": "disabledFeature",
      "params": [
        {
          "name": "feature",
          "type": "string"
        },
        {
          "name": "description",
          "type": "string"
        }
      ],
      "type": "DisabledFeature"
    },
    {
      "id": "1815593308",
      "predicate": "documentAttributeImageSize",
      "params": [
        {
          "name": "w",
          "type": "int"
        },
        {
          "name": "h",
          "type": "int"
        }
      ],
      "type": "DocumentAttribute"
    },
    {
      "id": "297109817",
      "predicate": "documentAttributeAnimated",
      "params": [],
      "type": "DocumentAttribute"
    },
    {
      "id": "1662637586",
      "predicate": "documentAttributeSticker",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "mask",
          "type": "flags.1?true"
        },
        {
          "name": "alt",
          "type": "string"
        },
        {
          "name": "stickerset",
          "type": "InputStickerSet"
        },
        {
          "name": "mask_coords",
          "type": "flags.0?MaskCoords"
        }
      ],
      "type": "DocumentAttribute"
    },
    {
      "id": "250621158",
      "predicate": "documentAttributeVideo",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "round_message",
          "type": "flags.0?true"
        },
        {
          "name": "duration",
          "type": "int"
        },
        {
          "name": "w",
          "type": "int"
        },
        {
          "name": "h",
          "type": "int"
        }
      ],
      "type": "DocumentAttribute"
    },
    {
      "id": "-1739392570",
      "predicate": "documentAttributeAudio",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "voice",
          "type": "flags.10?true"
        },
        {
          "name": "duration",
          "type": "int"
        },
        {
          "name": "title",
          "type": "flags.0?string"
        },
        {
          "name": "performer",
          "type": "flags.1?string"
        },
        {
          "name": "waveform",
          "type": "flags.2?bytes"
        }
      ],
      "type": "DocumentAttribute"
    },
    {
      "id": "358154344",
      "predicate": "documentAttributeFilename",
      "params": [
        {
          "name": "file_name",
          "type": "string"
        }
      ],
      "type": "DocumentAttribute"
    },
    {
      "id": "-244016606",
      "predicate": "messages.stickersNotModified",
      "params": [],
      "type": "messages.Stickers"
    },
    {
      "id": "-1970352846",
      "predicate": "messages.stickers",
      "params": [
        {
          "name": "hash",
          "type": "string"
        },
        {
          "name": "stickers",
          "type": "Vector<Document>"
        }
      ],
      "type": "messages.Stickers"
    },
    {
      "id": "313694676",
      "predicate": "stickerPack",
      "params": [
        {
          "name": "emoticon",
          "type": "string"
        },
        {
          "name": "documents",
          "type": "Vector<long>"
        }
      ],
      "type": "StickerPack"
    },
    {
      "id": "-395967805",
      "predicate": "messages.allStickersNotModified",
      "params": [],
      "type": "messages.AllStickers"
    },
    {
      "id": "-302170017",
      "predicate": "messages.allStickers",
      "params": [
        {
          "name": "hash",
          "type": "int"
        },
        {
          "name": "sets",
          "type": "Vector<StickerSet>"
        }
      ],
      "type": "messages.AllStickers"
    },
    {
      "id": "-1764049896",
      "predicate": "account.noPassword",
      "params": [
        {
          "name": "new_salt",
          "type": "bytes"
        },
        {
          "name": "email_unconfirmed_pattern",
          "type": "string"
        }
      ],
      "type": "account.Password"
    },
    {
      "id": "2081952796",
      "predicate": "account.password",
      "params": [
        {
          "name": "current_salt",
          "type": "bytes"
        },
        {
          "name": "new_salt",
          "type": "bytes"
        },
        {
          "name": "hint",
          "type": "string"
        },
        {
          "name": "has_recovery",
          "type": "Bool"
        },
        {
          "name": "email_unconfirmed_pattern",
          "type": "string"
        }
      ],
      "type": "account.Password"
    },
    {
      "id": "-1721631396",
      "predicate": "updateReadHistoryInbox",
      "params": [
        {
          "name": "peer",
          "type": "Peer"
        },
        {
          "name": "max_id",
          "type": "int"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "791617983",
      "predicate": "updateReadHistoryOutbox",
      "params": [
        {
          "name": "peer",
          "type": "Peer"
        },
        {
          "name": "max_id",
          "type": "int"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-2066640507",
      "predicate": "messages.affectedMessages",
      "params": [
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        }
      ],
      "type": "messages.AffectedMessages"
    },
    {
      "id": "1599050311",
      "predicate": "contactLinkUnknown",
      "params": [],
      "type": "ContactLink"
    },
    {
      "id": "-17968211",
      "predicate": "contactLinkNone",
      "params": [],
      "type": "ContactLink"
    },
    {
      "id": "646922073",
      "predicate": "contactLinkHasPhone",
      "params": [],
      "type": "ContactLink"
    },
    {
      "id": "-721239344",
      "predicate": "contactLinkContact",
      "params": [],
      "type": "ContactLink"
    },
    {
      "id": "2139689491",
      "predicate": "updateWebPage",
      "params": [
        {
          "name": "webpage",
          "type": "WebPage"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-350980120",
      "predicate": "webPageEmpty",
      "params": [
        {
          "name": "id",
          "type": "long"
        }
      ],
      "type": "WebPage"
    },
    {
      "id": "-981018084",
      "predicate": "webPagePending",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "date",
          "type": "int"
        }
      ],
      "type": "WebPage"
    },
    {
      "id": "1594340540",
      "predicate": "webPage",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "url",
          "type": "string"
        },
        {
          "name": "display_url",
          "type": "string"
        },
        {
          "name": "hash",
          "type": "int"
        },
        {
          "name": "type",
          "type": "flags.0?string"
        },
        {
          "name": "site_name",
          "type": "flags.1?string"
        },
        {
          "name": "title",
          "type": "flags.2?string"
        },
        {
          "name": "description",
          "type": "flags.3?string"
        },
        {
          "name": "photo",
          "type": "flags.4?Photo"
        },
        {
          "name": "embed_url",
          "type": "flags.5?string"
        },
        {
          "name": "embed_type",
          "type": "flags.5?string"
        },
        {
          "name": "embed_width",
          "type": "flags.6?int"
        },
        {
          "name": "embed_height",
          "type": "flags.6?int"
        },
        {
          "name": "duration",
          "type": "flags.7?int"
        },
        {
          "name": "author",
          "type": "flags.8?string"
        },
        {
          "name": "document",
          "type": "flags.9?Document"
        },
        {
          "name": "cached_page",
          "type": "flags.10?Page"
        }
      ],
      "type": "WebPage"
    },
    {
      "id": "-1557277184",
      "predicate": "messageMediaWebPage",
      "params": [
        {
          "name": "webpage",
          "type": "WebPage"
        }
      ],
      "type": "MessageMedia"
    },
    {
      "id": "2079516406",
      "predicate": "authorization",
      "params": [
        {
          "name": "hash",
          "type": "long"
        },
        {
          "name": "flags",
          "type": "int"
        },
        {
          "name": "device_model",
          "type": "string"
        },
        {
          "name": "platform",
          "type": "string"
        },
        {
          "name": "system_version",
          "type": "string"
        },
        {
          "name": "api_id",
          "type": "int"
        },
        {
          "name": "app_name",
          "type": "string"
        },
        {
          "name": "app_version",
          "type": "string"
        },
        {
          "name": "date_created",
          "type": "int"
        },
        {
          "name": "date_active",
          "type": "int"
        },
        {
          "name": "ip",
          "type": "string"
        },
        {
          "name": "country",
          "type": "string"
        },
        {
          "name": "region",
          "type": "string"
        }
      ],
      "type": "Authorization"
    },
    {
      "id": "307276766",
      "predicate": "account.authorizations",
      "params": [
        {
          "name": "authorizations",
          "type": "Vector<Authorization>"
        }
      ],
      "type": "account.Authorizations"
    },
    {
      "id": "-1212732749",
      "predicate": "account.passwordSettings",
      "params": [
        {
          "name": "email",
          "type": "string"
        }
      ],
      "type": "account.PasswordSettings"
    },
    {
      "id": "-2037289493",
      "predicate": "account.passwordInputSettings",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "new_salt",
          "type": "flags.0?bytes"
        },
        {
          "name": "new_password_hash",
          "type": "flags.0?bytes"
        },
        {
          "name": "hint",
          "type": "flags.0?string"
        },
        {
          "name": "email",
          "type": "flags.1?string"
        }
      ],
      "type": "account.PasswordInputSettings"
    },
    {
      "id": "326715557",
      "predicate": "auth.passwordRecovery",
      "params": [
        {
          "name": "email_pattern",
          "type": "string"
        }
      ],
      "type": "auth.PasswordRecovery"
    },
    {
      "id": "673687578",
      "predicate": "inputMediaVenue",
      "params": [
        {
          "name": "geo_point",
          "type": "InputGeoPoint"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "address",
          "type": "string"
        },
        {
          "name": "provider",
          "type": "string"
        },
        {
          "name": "venue_id",
          "type": "string"
        }
      ],
      "type": "InputMedia"
    },
    {
      "id": "2031269663",
      "predicate": "messageMediaVenue",
      "params": [
        {
          "name": "geo",
          "type": "GeoPoint"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "address",
          "type": "string"
        },
        {
          "name": "provider",
          "type": "string"
        },
        {
          "name": "venue_id",
          "type": "string"
        }
      ],
      "type": "MessageMedia"
    },
    {
      "id": "-1551583367",
      "predicate": "receivedNotifyMessage",
      "params": [
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "flags",
          "type": "int"
        }
      ],
      "type": "ReceivedNotifyMessage"
    },
    {
      "id": "1776236393",
      "predicate": "chatInviteEmpty",
      "params": [],
      "type": "ExportedChatInvite"
    },
    {
      "id": "-64092740",
      "predicate": "chatInviteExported",
      "params": [
        {
          "name": "link",
          "type": "string"
        }
      ],
      "type": "ExportedChatInvite"
    },
    {
      "id": "1516793212",
      "predicate": "chatInviteAlready",
      "params": [
        {
          "name": "chat",
          "type": "Chat"
        }
      ],
      "type": "ChatInvite"
    },
    {
      "id": "-613092008",
      "predicate": "chatInvite",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "channel",
          "type": "flags.0?true"
        },
        {
          "name": "broadcast",
          "type": "flags.1?true"
        },
        {
          "name": "public",
          "type": "flags.2?true"
        },
        {
          "name": "megagroup",
          "type": "flags.3?true"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "photo",
          "type": "ChatPhoto"
        },
        {
          "name": "participants_count",
          "type": "int"
        },
        {
          "name": "participants",
          "type": "flags.4?Vector<User>"
        }
      ],
      "type": "ChatInvite"
    },
    {
      "id": "-123931160",
      "predicate": "messageActionChatJoinedByLink",
      "params": [
        {
          "name": "inviter_id",
          "type": "int"
        }
      ],
      "type": "MessageAction"
    },
    {
      "id": "1757493555",
      "predicate": "updateReadMessagesContents",
      "params": [
        {
          "name": "messages",
          "type": "Vector<int>"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-4838507",
      "predicate": "inputStickerSetEmpty",
      "params": [],
      "type": "InputStickerSet"
    },
    {
      "id": "-1645763991",
      "predicate": "inputStickerSetID",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        }
      ],
      "type": "InputStickerSet"
    },
    {
      "id": "-2044933984",
      "predicate": "inputStickerSetShortName",
      "params": [
        {
          "name": "short_name",
          "type": "string"
        }
      ],
      "type": "InputStickerSet"
    },
    {
      "id": "-852477119",
      "predicate": "stickerSet",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "installed",
          "type": "flags.0?true"
        },
        {
          "name": "archived",
          "type": "flags.1?true"
        },
        {
          "name": "official",
          "type": "flags.2?true"
        },
        {
          "name": "masks",
          "type": "flags.3?true"
        },
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "short_name",
          "type": "string"
        },
        {
          "name": "count",
          "type": "int"
        },
        {
          "name": "hash",
          "type": "int"
        }
      ],
      "type": "StickerSet"
    },
    {
      "id": "-1240849242",
      "predicate": "messages.stickerSet",
      "params": [
        {
          "name": "set",
          "type": "StickerSet"
        },
        {
          "name": "packs",
          "type": "Vector<StickerPack>"
        },
        {
          "name": "documents",
          "type": "Vector<Document>"
        }
      ],
      "type": "messages.StickerSet"
    },
    {
      "id": "773059779",
      "predicate": "user",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "self",
          "type": "flags.10?true"
        },
        {
          "name": "contact",
          "type": "flags.11?true"
        },
        {
          "name": "mutual_contact",
          "type": "flags.12?true"
        },
        {
          "name": "deleted",
          "type": "flags.13?true"
        },
        {
          "name": "bot",
          "type": "flags.14?true"
        },
        {
          "name": "bot_chat_history",
          "type": "flags.15?true"
        },
        {
          "name": "bot_nochats",
          "type": "flags.16?true"
        },
        {
          "name": "verified",
          "type": "flags.17?true"
        },
        {
          "name": "restricted",
          "type": "flags.18?true"
        },
        {
          "name": "min",
          "type": "flags.20?true"
        },
        {
          "name": "bot_inline_geo",
          "type": "flags.21?true"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "access_hash",
          "type": "flags.0?long"
        },
        {
          "name": "first_name",
          "type": "flags.1?string"
        },
        {
          "name": "last_name",
          "type": "flags.2?string"
        },
        {
          "name": "username",
          "type": "flags.3?string"
        },
        {
          "name": "phone",
          "type": "flags.4?string"
        },
        {
          "name": "photo",
          "type": "flags.5?UserProfilePhoto"
        },
        {
          "name": "status",
          "type": "flags.6?UserStatus"
        },
        {
          "name": "bot_info_version",
          "type": "flags.14?int"
        },
        {
          "name": "restriction_reason",
          "type": "flags.18?string"
        },
        {
          "name": "bot_inline_placeholder",
          "type": "flags.19?string"
        },
        {
          "name": "lang_code",
          "type": "flags.22?string"
        }
      ],
      "type": "User"
    },
    {
      "id": "-1032140601",
      "predicate": "botCommand",
      "params": [
        {
          "name": "command",
          "type": "string"
        },
        {
          "name": "description",
          "type": "string"
        }
      ],
      "type": "BotCommand"
    },
    {
      "id": "-1729618630",
      "predicate": "botInfo",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "description",
          "type": "string"
        },
        {
          "name": "commands",
          "type": "Vector<BotCommand>"
        }
      ],
      "type": "BotInfo"
    },
    {
      "id": "-1560655744",
      "predicate": "keyboardButton",
      "params": [
        {
          "name": "text",
          "type": "string"
        }
      ],
      "type": "KeyboardButton"
    },
    {
      "id": "2002815875",
      "predicate": "keyboardButtonRow",
      "params": [
        {
          "name": "buttons",
          "type": "Vector<KeyboardButton>"
        }
      ],
      "type": "KeyboardButtonRow"
    },
    {
      "id": "-1606526075",
      "predicate": "replyKeyboardHide",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "selective",
          "type": "flags.2?true"
        }
      ],
      "type": "ReplyMarkup"
    },
    {
      "id": "-200242528",
      "predicate": "replyKeyboardForceReply",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "single_use",
          "type": "flags.1?true"
        },
        {
          "name": "selective",
          "type": "flags.2?true"
        }
      ],
      "type": "ReplyMarkup"
    },
    {
      "id": "889353612",
      "predicate": "replyKeyboardMarkup",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "resize",
          "type": "flags.0?true"
        },
        {
          "name": "single_use",
          "type": "flags.1?true"
        },
        {
          "name": "selective",
          "type": "flags.2?true"
        },
        {
          "name": "rows",
          "type": "Vector<KeyboardButtonRow>"
        }
      ],
      "type": "ReplyMarkup"
    },
    {
      "id": "2129714567",
      "predicate": "inputMessagesFilterUrl",
      "params": [],
      "type": "MessagesFilter"
    },
    {
      "id": "2072935910",
      "predicate": "inputPeerUser",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "access_hash",
          "type": "long"
        }
      ],
      "type": "InputPeer"
    },
    {
      "id": "-668391402",
      "predicate": "inputUser",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "access_hash",
          "type": "long"
        }
      ],
      "type": "InputUser"
    },
    {
      "id": "-1148011883",
      "predicate": "messageEntityUnknown",
      "params": [
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "length",
          "type": "int"
        }
      ],
      "type": "MessageEntity"
    },
    {
      "id": "-100378723",
      "predicate": "messageEntityMention",
      "params": [
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "length",
          "type": "int"
        }
      ],
      "type": "MessageEntity"
    },
    {
      "id": "1868782349",
      "predicate": "messageEntityHashtag",
      "params": [
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "length",
          "type": "int"
        }
      ],
      "type": "MessageEntity"
    },
    {
      "id": "1827637959",
      "predicate": "messageEntityBotCommand",
      "params": [
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "length",
          "type": "int"
        }
      ],
      "type": "MessageEntity"
    },
    {
      "id": "1859134776",
      "predicate": "messageEntityUrl",
      "params": [
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "length",
          "type": "int"
        }
      ],
      "type": "MessageEntity"
    },
    {
      "id": "1692693954",
      "predicate": "messageEntityEmail",
      "params": [
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "length",
          "type": "int"
        }
      ],
      "type": "MessageEntity"
    },
    {
      "id": "-1117713463",
      "predicate": "messageEntityBold",
      "params": [
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "length",
          "type": "int"
        }
      ],
      "type": "MessageEntity"
    },
    {
      "id": "-2106619040",
      "predicate": "messageEntityItalic",
      "params": [
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "length",
          "type": "int"
        }
      ],
      "type": "MessageEntity"
    },
    {
      "id": "681706865",
      "predicate": "messageEntityCode",
      "params": [
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "length",
          "type": "int"
        }
      ],
      "type": "MessageEntity"
    },
    {
      "id": "1938967520",
      "predicate": "messageEntityPre",
      "params": [
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "length",
          "type": "int"
        },
        {
          "name": "language",
          "type": "string"
        }
      ],
      "type": "MessageEntity"
    },
    {
      "id": "1990644519",
      "predicate": "messageEntityTextUrl",
      "params": [
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "length",
          "type": "int"
        },
        {
          "name": "url",
          "type": "string"
        }
      ],
      "type": "MessageEntity"
    },
    {
      "id": "301019932",
      "predicate": "updateShortSentMessage",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "out",
          "type": "flags.1?true"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "media",
          "type": "flags.9?MessageMedia"
        },
        {
          "name": "entities",
          "type": "flags.7?Vector<MessageEntity>"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "548253432",
      "predicate": "inputPeerChannel",
      "params": [
        {
          "name": "channel_id",
          "type": "int"
        },
        {
          "name": "access_hash",
          "type": "long"
        }
      ],
      "type": "InputPeer"
    },
    {
      "id": "-1109531342",
      "predicate": "peerChannel",
      "params": [
        {
          "name": "channel_id",
          "type": "int"
        }
      ],
      "type": "Peer"
    },
    {
      "id": "213142300",
      "predicate": "channel",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "creator",
          "type": "flags.0?true"
        },
        {
          "name": "left",
          "type": "flags.2?true"
        },
        {
          "name": "editor",
          "type": "flags.3?true"
        },
        {
          "name": "broadcast",
          "type": "flags.5?true"
        },
        {
          "name": "verified",
          "type": "flags.7?true"
        },
        {
          "name": "megagroup",
          "type": "flags.8?true"
        },
        {
          "name": "restricted",
          "type": "flags.9?true"
        },
        {
          "name": "democracy",
          "type": "flags.10?true"
        },
        {
          "name": "signatures",
          "type": "flags.11?true"
        },
        {
          "name": "min",
          "type": "flags.12?true"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "access_hash",
          "type": "flags.13?long"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "username",
          "type": "flags.6?string"
        },
        {
          "name": "photo",
          "type": "ChatPhoto"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "version",
          "type": "int"
        },
        {
          "name": "restriction_reason",
          "type": "flags.9?string"
        },
        {
          "name": "admin_rights",
          "type": "flags.14?ChannelAdminRights"
        },
        {
          "name": "banned_rights",
          "type": "flags.15?ChannelBannedRights"
        }
      ],
      "type": "Chat"
    },
    {
      "id": "681420594",
      "predicate": "channelForbidden",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "broadcast",
          "type": "flags.5?true"
        },
        {
          "name": "megagroup",
          "type": "flags.8?true"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "access_hash",
          "type": "long"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "until_date",
          "type": "flags.16?int"
        }
      ],
      "type": "Chat"
    },
    {
      "id": "401891279",
      "predicate": "channelFull",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "can_view_participants",
          "type": "flags.3?true"
        },
        {
          "name": "can_set_username",
          "type": "flags.6?true"
        },
        {
          "name": "can_set_stickers",
          "type": "flags.7?true"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "about",
          "type": "string"
        },
        {
          "name": "participants_count",
          "type": "flags.0?int"
        },
        {
          "name": "admins_count",
          "type": "flags.1?int"
        },
        {
          "name": "kicked_count",
          "type": "flags.2?int"
        },
        {
          "name": "banned_count",
          "type": "flags.2?int"
        },
        {
          "name": "read_inbox_max_id",
          "type": "int"
        },
        {
          "name": "read_outbox_max_id",
          "type": "int"
        },
        {
          "name": "unread_count",
          "type": "int"
        },
        {
          "name": "chat_photo",
          "type": "Photo"
        },
        {
          "name": "notify_settings",
          "type": "PeerNotifySettings"
        },
        {
          "name": "exported_invite",
          "type": "ExportedChatInvite"
        },
        {
          "name": "bot_info",
          "type": "Vector<BotInfo>"
        },
        {
          "name": "migrated_from_chat_id",
          "type": "flags.4?int"
        },
        {
          "name": "migrated_from_max_id",
          "type": "flags.4?int"
        },
        {
          "name": "pinned_msg_id",
          "type": "flags.5?int"
        },
        {
          "name": "stickerset",
          "type": "flags.8?StickerSet"
        }
      ],
      "type": "ChatFull"
    },
    {
      "id": "-1781355374",
      "predicate": "messageActionChannelCreate",
      "params": [
        {
          "name": "title",
          "type": "string"
        }
      ],
      "type": "MessageAction"
    },
    {
      "id": "-1725551049",
      "predicate": "messages.channelMessages",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "count",
          "type": "int"
        },
        {
          "name": "messages",
          "type": "Vector<Message>"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "messages.Messages"
    },
    {
      "id": "-352032773",
      "predicate": "updateChannelTooLong",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "channel_id",
          "type": "int"
        },
        {
          "name": "pts",
          "type": "flags.0?int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1227598250",
      "predicate": "updateChannel",
      "params": [
        {
          "name": "channel_id",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "1656358105",
      "predicate": "updateNewChannelMessage",
      "params": [
        {
          "name": "message",
          "type": "Message"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "1108669311",
      "predicate": "updateReadChannelInbox",
      "params": [
        {
          "name": "channel_id",
          "type": "int"
        },
        {
          "name": "max_id",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1015733815",
      "predicate": "updateDeleteChannelMessages",
      "params": [
        {
          "name": "channel_id",
          "type": "int"
        },
        {
          "name": "messages",
          "type": "Vector<int>"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1734268085",
      "predicate": "updateChannelMessageViews",
      "params": [
        {
          "name": "channel_id",
          "type": "int"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "views",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-292807034",
      "predicate": "inputChannelEmpty",
      "params": [],
      "type": "InputChannel"
    },
    {
      "id": "-1343524562",
      "predicate": "inputChannel",
      "params": [
        {
          "name": "channel_id",
          "type": "int"
        },
        {
          "name": "access_hash",
          "type": "long"
        }
      ],
      "type": "InputChannel"
    },
    {
      "id": "2131196633",
      "predicate": "contacts.resolvedPeer",
      "params": [
        {
          "name": "peer",
          "type": "Peer"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "contacts.ResolvedPeer"
    },
    {
      "id": "182649427",
      "predicate": "messageRange",
      "params": [
        {
          "name": "min_id",
          "type": "int"
        },
        {
          "name": "max_id",
          "type": "int"
        }
      ],
      "type": "MessageRange"
    },
    {
      "id": "1041346555",
      "predicate": "updates.channelDifferenceEmpty",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "final",
          "type": "flags.0?true"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "timeout",
          "type": "flags.1?int"
        }
      ],
      "type": "updates.ChannelDifference"
    },
    {
      "id": "1788705589",
      "predicate": "updates.channelDifferenceTooLong",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "final",
          "type": "flags.0?true"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "timeout",
          "type": "flags.1?int"
        },
        {
          "name": "top_message",
          "type": "int"
        },
        {
          "name": "read_inbox_max_id",
          "type": "int"
        },
        {
          "name": "read_outbox_max_id",
          "type": "int"
        },
        {
          "name": "unread_count",
          "type": "int"
        },
        {
          "name": "unread_mentions_count",
          "type": "int"
        },
        {
          "name": "messages",
          "type": "Vector<Message>"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "updates.ChannelDifference"
    },
    {
      "id": "543450958",
      "predicate": "updates.channelDifference",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "final",
          "type": "flags.0?true"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "timeout",
          "type": "flags.1?int"
        },
        {
          "name": "new_messages",
          "type": "Vector<Message>"
        },
        {
          "name": "other_updates",
          "type": "Vector<Update>"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "updates.ChannelDifference"
    },
    {
      "id": "-1798033689",
      "predicate": "channelMessagesFilterEmpty",
      "params": [],
      "type": "ChannelMessagesFilter"
    },
    {
      "id": "-847783593",
      "predicate": "channelMessagesFilter",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "exclude_new_messages",
          "type": "flags.1?true"
        },
        {
          "name": "ranges",
          "type": "Vector<MessageRange>"
        }
      ],
      "type": "ChannelMessagesFilter"
    },
    {
      "id": "367766557",
      "predicate": "channelParticipant",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        }
      ],
      "type": "ChannelParticipant"
    },
    {
      "id": "-1557620115",
      "predicate": "channelParticipantSelf",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "inviter_id",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        }
      ],
      "type": "ChannelParticipant"
    },
    {
      "id": "-471670279",
      "predicate": "channelParticipantCreator",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        }
      ],
      "type": "ChannelParticipant"
    },
    {
      "id": "-566281095",
      "predicate": "channelParticipantsRecent",
      "params": [],
      "type": "ChannelParticipantsFilter"
    },
    {
      "id": "-1268741783",
      "predicate": "channelParticipantsAdmins",
      "params": [],
      "type": "ChannelParticipantsFilter"
    },
    {
      "id": "-1548400251",
      "predicate": "channelParticipantsKicked",
      "params": [
        {
          "name": "q",
          "type": "string"
        }
      ],
      "type": "ChannelParticipantsFilter"
    },
    {
      "id": "-177282392",
      "predicate": "channels.channelParticipants",
      "params": [
        {
          "name": "count",
          "type": "int"
        },
        {
          "name": "participants",
          "type": "Vector<ChannelParticipant>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "channels.ChannelParticipants"
    },
    {
      "id": "-791039645",
      "predicate": "channels.channelParticipant",
      "params": [
        {
          "name": "participant",
          "type": "ChannelParticipant"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "channels.ChannelParticipant"
    },
    {
      "id": "1072550713",
      "predicate": "true",
      "params": [],
      "type": "True"
    },
    {
      "id": "-636267638",
      "predicate": "chatParticipantCreator",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        }
      ],
      "type": "ChatParticipant"
    },
    {
      "id": "-489233354",
      "predicate": "chatParticipantAdmin",
      "params": [
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "inviter_id",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        }
      ],
      "type": "ChatParticipant"
    },
    {
      "id": "1855224129",
      "predicate": "updateChatAdmins",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "enabled",
          "type": "Bool"
        },
        {
          "name": "version",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1232070311",
      "predicate": "updateChatParticipantAdmin",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "is_admin",
          "type": "Bool"
        },
        {
          "name": "version",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "1371385889",
      "predicate": "messageActionChatMigrateTo",
      "params": [
        {
          "name": "channel_id",
          "type": "int"
        }
      ],
      "type": "MessageAction"
    },
    {
      "id": "-1336546578",
      "predicate": "messageActionChannelMigrateFrom",
      "params": [
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "chat_id",
          "type": "int"
        }
      ],
      "type": "MessageAction"
    },
    {
      "id": "-1328445861",
      "predicate": "channelParticipantsBots",
      "params": [],
      "type": "ChannelParticipantsFilter"
    },
    {
      "id": "1490799288",
      "predicate": "inputReportReasonSpam",
      "params": [],
      "type": "ReportReason"
    },
    {
      "id": "505595789",
      "predicate": "inputReportReasonViolence",
      "params": [],
      "type": "ReportReason"
    },
    {
      "id": "777640226",
      "predicate": "inputReportReasonPornography",
      "params": [],
      "type": "ReportReason"
    },
    {
      "id": "-512463606",
      "predicate": "inputReportReasonOther",
      "params": [
        {
          "name": "text",
          "type": "string"
        }
      ],
      "type": "ReportReason"
    },
    {
      "id": "1753886890",
      "predicate": "updateNewStickerSet",
      "params": [
        {
          "name": "stickerset",
          "type": "messages.StickerSet"
        }
      ],
      "type": "Update"
    },
    {
      "id": "196268545",
      "predicate": "updateStickerSetsOrder",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "masks",
          "type": "flags.0?true"
        },
        {
          "name": "order",
          "type": "Vector<long>"
        }
      ],
      "type": "Update"
    },
    {
      "id": "1135492588",
      "predicate": "updateStickerSets",
      "params": [],
      "type": "Update"
    },
    {
      "id": "-236044656",
      "predicate": "help.termsOfService",
      "params": [
        {
          "name": "text",
          "type": "string"
        }
      ],
      "type": "help.TermsOfService"
    },
    {
      "id": "372165663",
      "predicate": "foundGif",
      "params": [
        {
          "name": "url",
          "type": "string"
        },
        {
          "name": "thumb_url",
          "type": "string"
        },
        {
          "name": "content_url",
          "type": "string"
        },
        {
          "name": "content_type",
          "type": "string"
        },
        {
          "name": "w",
          "type": "int"
        },
        {
          "name": "h",
          "type": "int"
        }
      ],
      "type": "FoundGif"
    },
    {
      "id": "1212395773",
      "predicate": "inputMediaGifExternal",
      "params": [
        {
          "name": "url",
          "type": "string"
        },
        {
          "name": "q",
          "type": "string"
        }
      ],
      "type": "InputMedia"
    },
    {
      "id": "1158290442",
      "predicate": "messages.foundGifs",
      "params": [
        {
          "name": "next_offset",
          "type": "int"
        },
        {
          "name": "results",
          "type": "Vector<FoundGif>"
        }
      ],
      "type": "messages.FoundGifs"
    },
    {
      "id": "-3644025",
      "predicate": "inputMessagesFilterGif",
      "params": [],
      "type": "MessagesFilter"
    },
    {
      "id": "-1821035490",
      "predicate": "updateSavedGifs",
      "params": [],
      "type": "Update"
    },
    {
      "id": "1417832080",
      "predicate": "updateBotInlineQuery",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "query_id",
          "type": "long"
        },
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "query",
          "type": "string"
        },
        {
          "name": "geo",
          "type": "flags.0?GeoPoint"
        },
        {
          "name": "offset",
          "type": "string"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1670052855",
      "predicate": "foundGifCached",
      "params": [
        {
          "name": "url",
          "type": "string"
        },
        {
          "name": "photo",
          "type": "Photo"
        },
        {
          "name": "document",
          "type": "Document"
        }
      ],
      "type": "FoundGif"
    },
    {
      "id": "-402498398",
      "predicate": "messages.savedGifsNotModified",
      "params": [],
      "type": "messages.SavedGifs"
    },
    {
      "id": "772213157",
      "predicate": "messages.savedGifs",
      "params": [
        {
          "name": "hash",
          "type": "int"
        },
        {
          "name": "gifs",
          "type": "Vector<Document>"
        }
      ],
      "type": "messages.SavedGifs"
    },
    {
      "id": "691006739",
      "predicate": "inputBotInlineMessageMediaAuto",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "caption",
          "type": "string"
        },
        {
          "name": "reply_markup",
          "type": "flags.2?ReplyMarkup"
        }
      ],
      "type": "InputBotInlineMessage"
    },
    {
      "id": "1036876423",
      "predicate": "inputBotInlineMessageText",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "no_webpage",
          "type": "flags.0?true"
        },
        {
          "name": "message",
          "type": "string"
        },
        {
          "name": "entities",
          "type": "flags.1?Vector<MessageEntity>"
        },
        {
          "name": "reply_markup",
          "type": "flags.2?ReplyMarkup"
        }
      ],
      "type": "InputBotInlineMessage"
    },
    {
      "id": "750510426",
      "predicate": "inputBotInlineResult",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "id",
          "type": "string"
        },
        {
          "name": "type",
          "type": "string"
        },
        {
          "name": "title",
          "type": "flags.1?string"
        },
        {
          "name": "description",
          "type": "flags.2?string"
        },
        {
          "name": "url",
          "type": "flags.3?string"
        },
        {
          "name": "thumb_url",
          "type": "flags.4?string"
        },
        {
          "name": "content_url",
          "type": "flags.5?string"
        },
        {
          "name": "content_type",
          "type": "flags.5?string"
        },
        {
          "name": "w",
          "type": "flags.6?int"
        },
        {
          "name": "h",
          "type": "flags.6?int"
        },
        {
          "name": "duration",
          "type": "flags.7?int"
        },
        {
          "name": "send_message",
          "type": "InputBotInlineMessage"
        }
      ],
      "type": "InputBotInlineResult"
    },
    {
      "id": "175419739",
      "predicate": "botInlineMessageMediaAuto",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "caption",
          "type": "string"
        },
        {
          "name": "reply_markup",
          "type": "flags.2?ReplyMarkup"
        }
      ],
      "type": "BotInlineMessage"
    },
    {
      "id": "-1937807902",
      "predicate": "botInlineMessageText",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "no_webpage",
          "type": "flags.0?true"
        },
        {
          "name": "message",
          "type": "string"
        },
        {
          "name": "entities",
          "type": "flags.1?Vector<MessageEntity>"
        },
        {
          "name": "reply_markup",
          "type": "flags.2?ReplyMarkup"
        }
      ],
      "type": "BotInlineMessage"
    },
    {
      "id": "-1679053127",
      "predicate": "botInlineResult",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "id",
          "type": "string"
        },
        {
          "name": "type",
          "type": "string"
        },
        {
          "name": "title",
          "type": "flags.1?string"
        },
        {
          "name": "description",
          "type": "flags.2?string"
        },
        {
          "name": "url",
          "type": "flags.3?string"
        },
        {
          "name": "thumb_url",
          "type": "flags.4?string"
        },
        {
          "name": "content_url",
          "type": "flags.5?string"
        },
        {
          "name": "content_type",
          "type": "flags.5?string"
        },
        {
          "name": "w",
          "type": "flags.6?int"
        },
        {
          "name": "h",
          "type": "flags.6?int"
        },
        {
          "name": "duration",
          "type": "flags.7?int"
        },
        {
          "name": "send_message",
          "type": "BotInlineMessage"
        }
      ],
      "type": "BotInlineResult"
    },
    {
      "id": "-858565059",
      "predicate": "messages.botResults",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "gallery",
          "type": "flags.0?true"
        },
        {
          "name": "query_id",
          "type": "long"
        },
        {
          "name": "next_offset",
          "type": "flags.1?string"
        },
        {
          "name": "switch_pm",
          "type": "flags.2?InlineBotSwitchPM"
        },
        {
          "name": "results",
          "type": "Vector<BotInlineResult>"
        },
        {
          "name": "cache_time",
          "type": "int"
        }
      ],
      "type": "messages.BotResults"
    },
    {
      "id": "1358283666",
      "predicate": "inputMessagesFilterVoice",
      "params": [],
      "type": "MessagesFilter"
    },
    {
      "id": "928101534",
      "predicate": "inputMessagesFilterMusic",
      "params": [],
      "type": "MessagesFilter"
    },
    {
      "id": "239663460",
      "predicate": "updateBotInlineSend",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "query",
          "type": "string"
        },
        {
          "name": "geo",
          "type": "flags.0?GeoPoint"
        },
        {
          "name": "id",
          "type": "string"
        },
        {
          "name": "msg_id",
          "type": "flags.1?InputBotInlineMessageID"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1107622874",
      "predicate": "inputPrivacyKeyChatInvite",
      "params": [],
      "type": "InputPrivacyKey"
    },
    {
      "id": "1343122938",
      "predicate": "privacyKeyChatInvite",
      "params": [],
      "type": "PrivacyKey"
    },
    {
      "id": "457133559",
      "predicate": "updateEditChannelMessage",
      "params": [
        {
          "name": "message",
          "type": "Message"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "524838915",
      "predicate": "exportedMessageLink",
      "params": [
        {
          "name": "link",
          "type": "string"
        }
      ],
      "type": "ExportedMessageLink"
    },
    {
      "id": "-85986132",
      "predicate": "messageFwdHeader",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "from_id",
          "type": "flags.0?int"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "channel_id",
          "type": "flags.1?int"
        },
        {
          "name": "channel_post",
          "type": "flags.2?int"
        },
        {
          "name": "post_author",
          "type": "flags.3?string"
        }
      ],
      "type": "MessageFwdHeader"
    },
    {
      "id": "-1799538451",
      "predicate": "messageActionPinMessage",
      "params": [],
      "type": "MessageAction"
    },
    {
      "id": "-2122045747",
      "predicate": "peerSettings",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "report_spam",
          "type": "flags.0?true"
        }
      ],
      "type": "PeerSettings"
    },
    {
      "id": "-1738988427",
      "predicate": "updateChannelPinnedMessage",
      "params": [
        {
          "name": "channel_id",
          "type": "int"
        },
        {
          "name": "id",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "629866245",
      "predicate": "keyboardButtonUrl",
      "params": [
        {
          "name": "text",
          "type": "string"
        },
        {
          "name": "url",
          "type": "string"
        }
      ],
      "type": "KeyboardButton"
    },
    {
      "id": "1748655686",
      "predicate": "keyboardButtonCallback",
      "params": [
        {
          "name": "text",
          "type": "string"
        },
        {
          "name": "data",
          "type": "bytes"
        }
      ],
      "type": "KeyboardButton"
    },
    {
      "id": "-1318425559",
      "predicate": "keyboardButtonRequestPhone",
      "params": [
        {
          "name": "text",
          "type": "string"
        }
      ],
      "type": "KeyboardButton"
    },
    {
      "id": "-59151553",
      "predicate": "keyboardButtonRequestGeoLocation",
      "params": [
        {
          "name": "text",
          "type": "string"
        }
      ],
      "type": "KeyboardButton"
    },
    {
      "id": "1923290508",
      "predicate": "auth.codeTypeSms",
      "params": [],
      "type": "auth.CodeType"
    },
    {
      "id": "1948046307",
      "predicate": "auth.codeTypeCall",
      "params": [],
      "type": "auth.CodeType"
    },
    {
      "id": "577556219",
      "predicate": "auth.codeTypeFlashCall",
      "params": [],
      "type": "auth.CodeType"
    },
    {
      "id": "1035688326",
      "predicate": "auth.sentCodeTypeApp",
      "params": [
        {
          "name": "length",
          "type": "int"
        }
      ],
      "type": "auth.SentCodeType"
    },
    {
      "id": "-1073693790",
      "predicate": "auth.sentCodeTypeSms",
      "params": [
        {
          "name": "length",
          "type": "int"
        }
      ],
      "type": "auth.SentCodeType"
    },
    {
      "id": "1398007207",
      "predicate": "auth.sentCodeTypeCall",
      "params": [
        {
          "name": "length",
          "type": "int"
        }
      ],
      "type": "auth.SentCodeType"
    },
    {
      "id": "-1425815847",
      "predicate": "auth.sentCodeTypeFlashCall",
      "params": [
        {
          "name": "pattern",
          "type": "string"
        }
      ],
      "type": "auth.SentCodeType"
    },
    {
      "id": "90744648",
      "predicate": "keyboardButtonSwitchInline",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "same_peer",
          "type": "flags.0?true"
        },
        {
          "name": "text",
          "type": "string"
        },
        {
          "name": "query",
          "type": "string"
        }
      ],
      "type": "KeyboardButton"
    },
    {
      "id": "1218642516",
      "predicate": "replyInlineMarkup",
      "params": [
        {
          "name": "rows",
          "type": "Vector<KeyboardButtonRow>"
        }
      ],
      "type": "ReplyMarkup"
    },
    {
      "id": "911761060",
      "predicate": "messages.botCallbackAnswer",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "alert",
          "type": "flags.1?true"
        },
        {
          "name": "has_url",
          "type": "flags.3?true"
        },
        {
          "name": "message",
          "type": "flags.0?string"
        },
        {
          "name": "url",
          "type": "flags.2?string"
        },
        {
          "name": "cache_time",
          "type": "int"
        }
      ],
      "type": "messages.BotCallbackAnswer"
    },
    {
      "id": "-415938591",
      "predicate": "updateBotCallbackQuery",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "query_id",
          "type": "long"
        },
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "peer",
          "type": "Peer"
        },
        {
          "name": "msg_id",
          "type": "int"
        },
        {
          "name": "chat_instance",
          "type": "long"
        },
        {
          "name": "data",
          "type": "flags.0?bytes"
        },
        {
          "name": "game_short_name",
          "type": "flags.1?string"
        }
      ],
      "type": "Update"
    },
    {
      "id": "649453030",
      "predicate": "messages.messageEditData",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "caption",
          "type": "flags.0?true"
        }
      ],
      "type": "messages.MessageEditData"
    },
    {
      "id": "-469536605",
      "predicate": "updateEditMessage",
      "params": [
        {
          "name": "message",
          "type": "Message"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-190472735",
      "predicate": "inputBotInlineMessageMediaGeo",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "geo_point",
          "type": "InputGeoPoint"
        },
        {
          "name": "reply_markup",
          "type": "flags.2?ReplyMarkup"
        }
      ],
      "type": "InputBotInlineMessage"
    },
    {
      "id": "-1431327288",
      "predicate": "inputBotInlineMessageMediaVenue",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "geo_point",
          "type": "InputGeoPoint"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "address",
          "type": "string"
        },
        {
          "name": "provider",
          "type": "string"
        },
        {
          "name": "venue_id",
          "type": "string"
        },
        {
          "name": "reply_markup",
          "type": "flags.2?ReplyMarkup"
        }
      ],
      "type": "InputBotInlineMessage"
    },
    {
      "id": "766443943",
      "predicate": "inputBotInlineMessageMediaContact",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "phone_number",
          "type": "string"
        },
        {
          "name": "first_name",
          "type": "string"
        },
        {
          "name": "last_name",
          "type": "string"
        },
        {
          "name": "reply_markup",
          "type": "flags.2?ReplyMarkup"
        }
      ],
      "type": "InputBotInlineMessage"
    },
    {
      "id": "982505656",
      "predicate": "botInlineMessageMediaGeo",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "geo",
          "type": "GeoPoint"
        },
        {
          "name": "reply_markup",
          "type": "flags.2?ReplyMarkup"
        }
      ],
      "type": "BotInlineMessage"
    },
    {
      "id": "1130767150",
      "predicate": "botInlineMessageMediaVenue",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "geo",
          "type": "GeoPoint"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "address",
          "type": "string"
        },
        {
          "name": "provider",
          "type": "string"
        },
        {
          "name": "venue_id",
          "type": "string"
        },
        {
          "name": "reply_markup",
          "type": "flags.2?ReplyMarkup"
        }
      ],
      "type": "BotInlineMessage"
    },
    {
      "id": "904770772",
      "predicate": "botInlineMessageMediaContact",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "phone_number",
          "type": "string"
        },
        {
          "name": "first_name",
          "type": "string"
        },
        {
          "name": "last_name",
          "type": "string"
        },
        {
          "name": "reply_markup",
          "type": "flags.2?ReplyMarkup"
        }
      ],
      "type": "BotInlineMessage"
    },
    {
      "id": "-1462213465",
      "predicate": "inputBotInlineResultPhoto",
      "params": [
        {
          "name": "id",
          "type": "string"
        },
        {
          "name": "type",
          "type": "string"
        },
        {
          "name": "photo",
          "type": "InputPhoto"
        },
        {
          "name": "send_message",
          "type": "InputBotInlineMessage"
        }
      ],
      "type": "InputBotInlineResult"
    },
    {
      "id": "-459324",
      "predicate": "inputBotInlineResultDocument",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "id",
          "type": "string"
        },
        {
          "name": "type",
          "type": "string"
        },
        {
          "name": "title",
          "type": "flags.1?string"
        },
        {
          "name": "description",
          "type": "flags.2?string"
        },
        {
          "name": "document",
          "type": "InputDocument"
        },
        {
          "name": "send_message",
          "type": "InputBotInlineMessage"
        }
      ],
      "type": "InputBotInlineResult"
    },
    {
      "id": "400266251",
      "predicate": "botInlineMediaResult",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "id",
          "type": "string"
        },
        {
          "name": "type",
          "type": "string"
        },
        {
          "name": "photo",
          "type": "flags.0?Photo"
        },
        {
          "name": "document",
          "type": "flags.1?Document"
        },
        {
          "name": "title",
          "type": "flags.2?string"
        },
        {
          "name": "description",
          "type": "flags.3?string"
        },
        {
          "name": "send_message",
          "type": "BotInlineMessage"
        }
      ],
      "type": "BotInlineResult"
    },
    {
      "id": "-1995686519",
      "predicate": "inputBotInlineMessageID",
      "params": [
        {
          "name": "dc_id",
          "type": "int"
        },
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        }
      ],
      "type": "InputBotInlineMessageID"
    },
    {
      "id": "-103646630",
      "predicate": "updateInlineBotCallbackQuery",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "query_id",
          "type": "long"
        },
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "msg_id",
          "type": "InputBotInlineMessageID"
        },
        {
          "name": "chat_instance",
          "type": "long"
        },
        {
          "name": "data",
          "type": "flags.0?bytes"
        },
        {
          "name": "game_short_name",
          "type": "flags.1?string"
        }
      ],
      "type": "Update"
    },
    {
      "id": "1008755359",
      "predicate": "inlineBotSwitchPM",
      "params": [
        {
          "name": "text",
          "type": "string"
        },
        {
          "name": "start_param",
          "type": "string"
        }
      ],
      "type": "InlineBotSwitchPM"
    },
    {
      "id": "892193368",
      "predicate": "messageEntityMentionName",
      "params": [
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "length",
          "type": "int"
        },
        {
          "name": "user_id",
          "type": "int"
        }
      ],
      "type": "MessageEntity"
    },
    {
      "id": "546203849",
      "predicate": "inputMessageEntityMentionName",
      "params": [
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "length",
          "type": "int"
        },
        {
          "name": "user_id",
          "type": "InputUser"
        }
      ],
      "type": "MessageEntity"
    },
    {
      "id": "863093588",
      "predicate": "messages.peerDialogs",
      "params": [
        {
          "name": "dialogs",
          "type": "Vector<Dialog>"
        },
        {
          "name": "messages",
          "type": "Vector<Message>"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        },
        {
          "name": "state",
          "type": "updates.State"
        }
      ],
      "type": "messages.PeerDialogs"
    },
    {
      "id": "-305282981",
      "predicate": "topPeer",
      "params": [
        {
          "name": "peer",
          "type": "Peer"
        },
        {
          "name": "rating",
          "type": "double"
        }
      ],
      "type": "TopPeer"
    },
    {
      "id": "-1419371685",
      "predicate": "topPeerCategoryBotsPM",
      "params": [],
      "type": "TopPeerCategory"
    },
    {
      "id": "344356834",
      "predicate": "topPeerCategoryBotsInline",
      "params": [],
      "type": "TopPeerCategory"
    },
    {
      "id": "104314861",
      "predicate": "topPeerCategoryCorrespondents",
      "params": [],
      "type": "TopPeerCategory"
    },
    {
      "id": "-1122524854",
      "predicate": "topPeerCategoryGroups",
      "params": [],
      "type": "TopPeerCategory"
    },
    {
      "id": "371037736",
      "predicate": "topPeerCategoryChannels",
      "params": [],
      "type": "TopPeerCategory"
    },
    {
      "id": "-75283823",
      "predicate": "topPeerCategoryPeers",
      "params": [
        {
          "name": "category",
          "type": "TopPeerCategory"
        },
        {
          "name": "count",
          "type": "int"
        },
        {
          "name": "peers",
          "type": "Vector<TopPeer>"
        }
      ],
      "type": "TopPeerCategoryPeers"
    },
    {
      "id": "-567906571",
      "predicate": "contacts.topPeersNotModified",
      "params": [],
      "type": "contacts.TopPeers"
    },
    {
      "id": "1891070632",
      "predicate": "contacts.topPeers",
      "params": [
        {
          "name": "categories",
          "type": "Vector<TopPeerCategoryPeers>"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "contacts.TopPeers"
    },
    {
      "id": "975236280",
      "predicate": "inputMessagesFilterChatPhotos",
      "params": [],
      "type": "MessagesFilter"
    },
    {
      "id": "634833351",
      "predicate": "updateReadChannelOutbox",
      "params": [
        {
          "name": "channel_id",
          "type": "int"
        },
        {
          "name": "max_id",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-299124375",
      "predicate": "updateDraftMessage",
      "params": [
        {
          "name": "peer",
          "type": "Peer"
        },
        {
          "name": "draft",
          "type": "DraftMessage"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1169445179",
      "predicate": "draftMessageEmpty",
      "params": [],
      "type": "DraftMessage"
    },
    {
      "id": "-40996577",
      "predicate": "draftMessage",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "no_webpage",
          "type": "flags.1?true"
        },
        {
          "name": "reply_to_msg_id",
          "type": "flags.0?int"
        },
        {
          "name": "message",
          "type": "string"
        },
        {
          "name": "entities",
          "type": "flags.3?Vector<MessageEntity>"
        },
        {
          "name": "date",
          "type": "int"
        }
      ],
      "type": "DraftMessage"
    },
    {
      "id": "-1615153660",
      "predicate": "messageActionHistoryClear",
      "params": [],
      "type": "MessageAction"
    },
    {
      "id": "1461528386",
      "predicate": "updateReadFeaturedStickers",
      "params": [],
      "type": "Update"
    },
    {
      "id": "-1706939360",
      "predicate": "updateRecentStickers",
      "params": [],
      "type": "Update"
    },
    {
      "id": "82699215",
      "predicate": "messages.featuredStickersNotModified",
      "params": [],
      "type": "messages.FeaturedStickers"
    },
    {
      "id": "-123893531",
      "predicate": "messages.featuredStickers",
      "params": [
        {
          "name": "hash",
          "type": "int"
        },
        {
          "name": "sets",
          "type": "Vector<StickerSetCovered>"
        },
        {
          "name": "unread",
          "type": "Vector<long>"
        }
      ],
      "type": "messages.FeaturedStickers"
    },
    {
      "id": "186120336",
      "predicate": "messages.recentStickersNotModified",
      "params": [],
      "type": "messages.RecentStickers"
    },
    {
      "id": "1558317424",
      "predicate": "messages.recentStickers",
      "params": [
        {
          "name": "hash",
          "type": "int"
        },
        {
          "name": "stickers",
          "type": "Vector<Document>"
        }
      ],
      "type": "messages.RecentStickers"
    },
    {
      "id": "1338747336",
      "predicate": "messages.archivedStickers",
      "params": [
        {
          "name": "count",
          "type": "int"
        },
        {
          "name": "sets",
          "type": "Vector<StickerSetCovered>"
        }
      ],
      "type": "messages.ArchivedStickers"
    },
    {
      "id": "946083368",
      "predicate": "messages.stickerSetInstallResultSuccess",
      "params": [],
      "type": "messages.StickerSetInstallResult"
    },
    {
      "id": "904138920",
      "predicate": "messages.stickerSetInstallResultArchive",
      "params": [
        {
          "name": "sets",
          "type": "Vector<StickerSetCovered>"
        }
      ],
      "type": "messages.StickerSetInstallResult"
    },
    {
      "id": "1678812626",
      "predicate": "stickerSetCovered",
      "params": [
        {
          "name": "set",
          "type": "StickerSet"
        },
        {
          "name": "cover",
          "type": "Document"
        }
      ],
      "type": "StickerSetCovered"
    },
    {
      "id": "153267905",
      "predicate": "inputMediaPhotoExternal",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "url",
          "type": "string"
        },
        {
          "name": "caption",
          "type": "string"
        },
        {
          "name": "ttl_seconds",
          "type": "flags.0?int"
        }
      ],
      "type": "InputMedia"
    },
    {
      "id": "-1225309387",
      "predicate": "inputMediaDocumentExternal",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "url",
          "type": "string"
        },
        {
          "name": "caption",
          "type": "string"
        },
        {
          "name": "ttl_seconds",
          "type": "flags.0?int"
        }
      ],
      "type": "InputMedia"
    },
    {
      "id": "-1574314746",
      "predicate": "updateConfig",
      "params": [],
      "type": "Update"
    },
    {
      "id": "861169551",
      "predicate": "updatePtsChanged",
      "params": [],
      "type": "Update"
    },
    {
      "id": "-1834538890",
      "predicate": "messageActionGameScore",
      "params": [
        {
          "name": "game_id",
          "type": "long"
        },
        {
          "name": "score",
          "type": "int"
        }
      ],
      "type": "MessageAction"
    },
    {
      "id": "-1744710921",
      "predicate": "documentAttributeHasStickers",
      "params": [],
      "type": "DocumentAttribute"
    },
    {
      "id": "1358175439",
      "predicate": "keyboardButtonGame",
      "params": [
        {
          "name": "text",
          "type": "string"
        }
      ],
      "type": "KeyboardButton"
    },
    {
      "id": "872932635",
      "predicate": "stickerSetMultiCovered",
      "params": [
        {
          "name": "set",
          "type": "StickerSet"
        },
        {
          "name": "covers",
          "type": "Vector<Document>"
        }
      ],
      "type": "StickerSetCovered"
    },
    {
      "id": "-1361650766",
      "predicate": "maskCoords",
      "params": [
        {
          "name": "n",
          "type": "int"
        },
        {
          "name": "x",
          "type": "double"
        },
        {
          "name": "y",
          "type": "double"
        },
        {
          "name": "zoom",
          "type": "double"
        }
      ],
      "type": "MaskCoords"
    },
    {
      "id": "1251549527",
      "predicate": "inputStickeredMediaPhoto",
      "params": [
        {
          "name": "id",
          "type": "InputPhoto"
        }
      ],
      "type": "InputStickeredMedia"
    },
    {
      "id": "70813275",
      "predicate": "inputStickeredMediaDocument",
      "params": [
        {
          "name": "id",
          "type": "InputDocument"
        }
      ],
      "type": "InputStickeredMedia"
    },
    {
      "id": "-750828557",
      "predicate": "inputMediaGame",
      "params": [
        {
          "name": "id",
          "type": "InputGame"
        }
      ],
      "type": "InputMedia"
    },
    {
      "id": "-38694904",
      "predicate": "messageMediaGame",
      "params": [
        {
          "name": "game",
          "type": "Game"
        }
      ],
      "type": "MessageMedia"
    },
    {
      "id": "1262639204",
      "predicate": "inputBotInlineMessageGame",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "reply_markup",
          "type": "flags.2?ReplyMarkup"
        }
      ],
      "type": "InputBotInlineMessage"
    },
    {
      "id": "1336154098",
      "predicate": "inputBotInlineResultGame",
      "params": [
        {
          "name": "id",
          "type": "string"
        },
        {
          "name": "short_name",
          "type": "string"
        },
        {
          "name": "send_message",
          "type": "InputBotInlineMessage"
        }
      ],
      "type": "InputBotInlineResult"
    },
    {
      "id": "-1107729093",
      "predicate": "game",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        },
        {
          "name": "short_name",
          "type": "string"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "description",
          "type": "string"
        },
        {
          "name": "photo",
          "type": "Photo"
        },
        {
          "name": "document",
          "type": "flags.0?Document"
        }
      ],
      "type": "Game"
    },
    {
      "id": "53231223",
      "predicate": "inputGameID",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        }
      ],
      "type": "InputGame"
    },
    {
      "id": "-1020139510",
      "predicate": "inputGameShortName",
      "params": [
        {
          "name": "bot_id",
          "type": "InputUser"
        },
        {
          "name": "short_name",
          "type": "string"
        }
      ],
      "type": "InputGame"
    },
    {
      "id": "1493171408",
      "predicate": "highScore",
      "params": [
        {
          "name": "pos",
          "type": "int"
        },
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "score",
          "type": "int"
        }
      ],
      "type": "HighScore"
    },
    {
      "id": "-1707344487",
      "predicate": "messages.highScores",
      "params": [
        {
          "name": "scores",
          "type": "Vector<HighScore>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "messages.HighScores"
    },
    {
      "id": "-1663561404",
      "predicate": "messages.chatsSlice",
      "params": [
        {
          "name": "count",
          "type": "int"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        }
      ],
      "type": "messages.Chats"
    },
    {
      "id": "1081547008",
      "predicate": "updateChannelWebPage",
      "params": [
        {
          "name": "channel_id",
          "type": "int"
        },
        {
          "name": "webpage",
          "type": "WebPage"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_count",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "1258196845",
      "predicate": "updates.differenceTooLong",
      "params": [
        {
          "name": "pts",
          "type": "int"
        }
      ],
      "type": "updates.Difference"
    },
    {
      "id": "-580219064",
      "predicate": "sendMessageGamePlayAction",
      "params": [],
      "type": "SendMessageAction"
    },
    {
      "id": "-2054908813",
      "predicate": "webPageNotModified",
      "params": [],
      "type": "WebPage"
    },
    {
      "id": "-599948721",
      "predicate": "textEmpty",
      "params": [],
      "type": "RichText"
    },
    {
      "id": "1950782688",
      "predicate": "textPlain",
      "params": [
        {
          "name": "text",
          "type": "string"
        }
      ],
      "type": "RichText"
    },
    {
      "id": "1730456516",
      "predicate": "textBold",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        }
      ],
      "type": "RichText"
    },
    {
      "id": "-653089380",
      "predicate": "textItalic",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        }
      ],
      "type": "RichText"
    },
    {
      "id": "-1054465340",
      "predicate": "textUnderline",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        }
      ],
      "type": "RichText"
    },
    {
      "id": "-1678197867",
      "predicate": "textStrike",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        }
      ],
      "type": "RichText"
    },
    {
      "id": "1816074681",
      "predicate": "textFixed",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        }
      ],
      "type": "RichText"
    },
    {
      "id": "1009288385",
      "predicate": "textUrl",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        },
        {
          "name": "url",
          "type": "string"
        },
        {
          "name": "webpage_id",
          "type": "long"
        }
      ],
      "type": "RichText"
    },
    {
      "id": "-564523562",
      "predicate": "textEmail",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        },
        {
          "name": "email",
          "type": "string"
        }
      ],
      "type": "RichText"
    },
    {
      "id": "2120376535",
      "predicate": "textConcat",
      "params": [
        {
          "name": "texts",
          "type": "Vector<RichText>"
        }
      ],
      "type": "RichText"
    },
    {
      "id": "1890305021",
      "predicate": "pageBlockTitle",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "-1879401953",
      "predicate": "pageBlockSubtitle",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "-1162877472",
      "predicate": "pageBlockAuthorDate",
      "params": [
        {
          "name": "author",
          "type": "RichText"
        },
        {
          "name": "published_date",
          "type": "int"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "-1076861716",
      "predicate": "pageBlockHeader",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "-248793375",
      "predicate": "pageBlockSubheader",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "1182402406",
      "predicate": "pageBlockParagraph",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "-1066346178",
      "predicate": "pageBlockPreformatted",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        },
        {
          "name": "language",
          "type": "string"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "1216809369",
      "predicate": "pageBlockFooter",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "-618614392",
      "predicate": "pageBlockDivider",
      "params": [],
      "type": "PageBlock"
    },
    {
      "id": "978896884",
      "predicate": "pageBlockList",
      "params": [
        {
          "name": "ordered",
          "type": "Bool"
        },
        {
          "name": "items",
          "type": "Vector<RichText>"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "641563686",
      "predicate": "pageBlockBlockquote",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        },
        {
          "name": "caption",
          "type": "RichText"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "1329878739",
      "predicate": "pageBlockPullquote",
      "params": [
        {
          "name": "text",
          "type": "RichText"
        },
        {
          "name": "caption",
          "type": "RichText"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "-372860542",
      "predicate": "pageBlockPhoto",
      "params": [
        {
          "name": "photo_id",
          "type": "long"
        },
        {
          "name": "caption",
          "type": "RichText"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "-640214938",
      "predicate": "pageBlockVideo",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "autoplay",
          "type": "flags.0?true"
        },
        {
          "name": "loop",
          "type": "flags.1?true"
        },
        {
          "name": "video_id",
          "type": "long"
        },
        {
          "name": "caption",
          "type": "RichText"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "972174080",
      "predicate": "pageBlockCover",
      "params": [
        {
          "name": "cover",
          "type": "PageBlock"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "-840826671",
      "predicate": "pageBlockEmbed",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "full_width",
          "type": "flags.0?true"
        },
        {
          "name": "allow_scrolling",
          "type": "flags.3?true"
        },
        {
          "name": "url",
          "type": "flags.1?string"
        },
        {
          "name": "html",
          "type": "flags.2?string"
        },
        {
          "name": "poster_photo_id",
          "type": "flags.4?long"
        },
        {
          "name": "w",
          "type": "int"
        },
        {
          "name": "h",
          "type": "int"
        },
        {
          "name": "caption",
          "type": "RichText"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "690781161",
      "predicate": "pageBlockEmbedPost",
      "params": [
        {
          "name": "url",
          "type": "string"
        },
        {
          "name": "webpage_id",
          "type": "long"
        },
        {
          "name": "author_photo_id",
          "type": "long"
        },
        {
          "name": "author",
          "type": "string"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "blocks",
          "type": "Vector<PageBlock>"
        },
        {
          "name": "caption",
          "type": "RichText"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "319588707",
      "predicate": "pageBlockSlideshow",
      "params": [
        {
          "name": "items",
          "type": "Vector<PageBlock>"
        },
        {
          "name": "caption",
          "type": "RichText"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "-1908433218",
      "predicate": "pagePart",
      "params": [
        {
          "name": "blocks",
          "type": "Vector<PageBlock>"
        },
        {
          "name": "photos",
          "type": "Vector<Photo>"
        },
        {
          "name": "documents",
          "type": "Vector<Document>"
        }
      ],
      "type": "Page"
    },
    {
      "id": "1433323434",
      "predicate": "pageFull",
      "params": [
        {
          "name": "blocks",
          "type": "Vector<PageBlock>"
        },
        {
          "name": "photos",
          "type": "Vector<Photo>"
        },
        {
          "name": "documents",
          "type": "Vector<Document>"
        }
      ],
      "type": "Page"
    },
    {
      "id": "-1425052898",
      "predicate": "updatePhoneCall",
      "params": [
        {
          "name": "phone_call",
          "type": "PhoneCall"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-686710068",
      "predicate": "updateDialogPinned",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "pinned",
          "type": "flags.0?true"
        },
        {
          "name": "peer",
          "type": "Peer"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-657787251",
      "predicate": "updatePinnedDialogs",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "order",
          "type": "flags.0?Vector<Peer>"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-88417185",
      "predicate": "inputPrivacyKeyPhoneCall",
      "params": [],
      "type": "InputPrivacyKey"
    },
    {
      "id": "1030105979",
      "predicate": "privacyKeyPhoneCall",
      "params": [],
      "type": "PrivacyKey"
    },
    {
      "id": "324435594",
      "predicate": "pageBlockUnsupported",
      "params": [],
      "type": "PageBlock"
    },
    {
      "id": "-837994576",
      "predicate": "pageBlockAnchor",
      "params": [
        {
          "name": "name",
          "type": "string"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "145955919",
      "predicate": "pageBlockCollage",
      "params": [
        {
          "name": "items",
          "type": "Vector<PageBlock>"
        },
        {
          "name": "caption",
          "type": "RichText"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "506920429",
      "predicate": "inputPhoneCall",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        }
      ],
      "type": "InputPhoneCall"
    },
    {
      "id": "1399245077",
      "predicate": "phoneCallEmpty",
      "params": [
        {
          "name": "id",
          "type": "long"
        }
      ],
      "type": "PhoneCall"
    },
    {
      "id": "462375633",
      "predicate": "phoneCallWaiting",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "admin_id",
          "type": "int"
        },
        {
          "name": "participant_id",
          "type": "int"
        },
        {
          "name": "protocol",
          "type": "PhoneCallProtocol"
        },
        {
          "name": "receive_date",
          "type": "flags.0?int"
        }
      ],
      "type": "PhoneCall"
    },
    {
      "id": "-2089411356",
      "predicate": "phoneCallRequested",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "admin_id",
          "type": "int"
        },
        {
          "name": "participant_id",
          "type": "int"
        },
        {
          "name": "g_a_hash",
          "type": "bytes"
        },
        {
          "name": "protocol",
          "type": "PhoneCallProtocol"
        }
      ],
      "type": "PhoneCall"
    },
    {
      "id": "-1660057",
      "predicate": "phoneCall",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "admin_id",
          "type": "int"
        },
        {
          "name": "participant_id",
          "type": "int"
        },
        {
          "name": "g_a_or_b",
          "type": "bytes"
        },
        {
          "name": "key_fingerprint",
          "type": "long"
        },
        {
          "name": "protocol",
          "type": "PhoneCallProtocol"
        },
        {
          "name": "connection",
          "type": "PhoneConnection"
        },
        {
          "name": "alternative_connections",
          "type": "Vector<PhoneConnection>"
        },
        {
          "name": "start_date",
          "type": "int"
        }
      ],
      "type": "PhoneCall"
    },
    {
      "id": "1355435489",
      "predicate": "phoneCallDiscarded",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "need_rating",
          "type": "flags.2?true"
        },
        {
          "name": "need_debug",
          "type": "flags.3?true"
        },
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "reason",
          "type": "flags.0?PhoneCallDiscardReason"
        },
        {
          "name": "duration",
          "type": "flags.1?int"
        }
      ],
      "type": "PhoneCall"
    },
    {
      "id": "-1655957568",
      "predicate": "phoneConnection",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "ip",
          "type": "string"
        },
        {
          "name": "ipv6",
          "type": "string"
        },
        {
          "name": "port",
          "type": "int"
        },
        {
          "name": "peer_tag",
          "type": "bytes"
        }
      ],
      "type": "PhoneConnection"
    },
    {
      "id": "-1564789301",
      "predicate": "phoneCallProtocol",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "udp_p2p",
          "type": "flags.0?true"
        },
        {
          "name": "udp_reflector",
          "type": "flags.1?true"
        },
        {
          "name": "min_layer",
          "type": "int"
        },
        {
          "name": "max_layer",
          "type": "int"
        }
      ],
      "type": "PhoneCallProtocol"
    },
    {
      "id": "-326966976",
      "predicate": "phone.phoneCall",
      "params": [
        {
          "name": "phone_call",
          "type": "PhoneCall"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "phone.PhoneCall"
    },
    {
      "id": "-2048646399",
      "predicate": "phoneCallDiscardReasonMissed",
      "params": [],
      "type": "PhoneCallDiscardReason"
    },
    {
      "id": "-527056480",
      "predicate": "phoneCallDiscardReasonDisconnect",
      "params": [],
      "type": "PhoneCallDiscardReason"
    },
    {
      "id": "1471006352",
      "predicate": "phoneCallDiscardReasonHangup",
      "params": [],
      "type": "PhoneCallDiscardReason"
    },
    {
      "id": "-84416311",
      "predicate": "phoneCallDiscardReasonBusy",
      "params": [],
      "type": "PhoneCallDiscardReason"
    },
    {
      "id": "-2134272152",
      "predicate": "inputMessagesFilterPhoneCalls",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "missed",
          "type": "flags.0?true"
        }
      ],
      "type": "MessagesFilter"
    },
    {
      "id": "-2132731265",
      "predicate": "messageActionPhoneCall",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "call_id",
          "type": "long"
        },
        {
          "name": "reason",
          "type": "flags.0?PhoneCallDiscardReason"
        },
        {
          "name": "duration",
          "type": "flags.1?int"
        }
      ],
      "type": "MessageAction"
    },
    {
      "id": "-1022713000",
      "predicate": "invoice",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "test",
          "type": "flags.0?true"
        },
        {
          "name": "name_requested",
          "type": "flags.1?true"
        },
        {
          "name": "phone_requested",
          "type": "flags.2?true"
        },
        {
          "name": "email_requested",
          "type": "flags.3?true"
        },
        {
          "name": "shipping_address_requested",
          "type": "flags.4?true"
        },
        {
          "name": "flexible",
          "type": "flags.5?true"
        },
        {
          "name": "currency",
          "type": "string"
        },
        {
          "name": "prices",
          "type": "Vector<LabeledPrice>"
        }
      ],
      "type": "Invoice"
    },
    {
      "id": "-1844103547",
      "predicate": "inputMediaInvoice",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "description",
          "type": "string"
        },
        {
          "name": "photo",
          "type": "flags.0?InputWebDocument"
        },
        {
          "name": "invoice",
          "type": "Invoice"
        },
        {
          "name": "payload",
          "type": "bytes"
        },
        {
          "name": "provider",
          "type": "string"
        },
        {
          "name": "start_param",
          "type": "string"
        }
      ],
      "type": "InputMedia"
    },
    {
      "id": "-1892568281",
      "predicate": "messageActionPaymentSentMe",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "currency",
          "type": "string"
        },
        {
          "name": "total_amount",
          "type": "long"
        },
        {
          "name": "payload",
          "type": "bytes"
        },
        {
          "name": "info",
          "type": "flags.0?PaymentRequestedInfo"
        },
        {
          "name": "shipping_option_id",
          "type": "flags.1?string"
        },
        {
          "name": "charge",
          "type": "PaymentCharge"
        }
      ],
      "type": "MessageAction"
    },
    {
      "id": "-2074799289",
      "predicate": "messageMediaInvoice",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "shipping_address_requested",
          "type": "flags.1?true"
        },
        {
          "name": "test",
          "type": "flags.3?true"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "description",
          "type": "string"
        },
        {
          "name": "photo",
          "type": "flags.0?WebDocument"
        },
        {
          "name": "receipt_msg_id",
          "type": "flags.2?int"
        },
        {
          "name": "currency",
          "type": "string"
        },
        {
          "name": "total_amount",
          "type": "long"
        },
        {
          "name": "start_param",
          "type": "string"
        }
      ],
      "type": "MessageMedia"
    },
    {
      "id": "-1344716869",
      "predicate": "keyboardButtonBuy",
      "params": [
        {
          "name": "text",
          "type": "string"
        }
      ],
      "type": "KeyboardButton"
    },
    {
      "id": "1080663248",
      "predicate": "messageActionPaymentSent",
      "params": [
        {
          "name": "currency",
          "type": "string"
        },
        {
          "name": "total_amount",
          "type": "long"
        }
      ],
      "type": "MessageAction"
    },
    {
      "id": "1062645411",
      "predicate": "payments.paymentForm",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "can_save_credentials",
          "type": "flags.2?true"
        },
        {
          "name": "password_missing",
          "type": "flags.3?true"
        },
        {
          "name": "bot_id",
          "type": "int"
        },
        {
          "name": "invoice",
          "type": "Invoice"
        },
        {
          "name": "provider_id",
          "type": "int"
        },
        {
          "name": "url",
          "type": "string"
        },
        {
          "name": "native_provider",
          "type": "flags.4?string"
        },
        {
          "name": "native_params",
          "type": "flags.4?DataJSON"
        },
        {
          "name": "saved_info",
          "type": "flags.0?PaymentRequestedInfo"
        },
        {
          "name": "saved_credentials",
          "type": "flags.1?PaymentSavedCredentials"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "payments.PaymentForm"
    },
    {
      "id": "512535275",
      "predicate": "postAddress",
      "params": [
        {
          "name": "street_line1",
          "type": "string"
        },
        {
          "name": "street_line2",
          "type": "string"
        },
        {
          "name": "city",
          "type": "string"
        },
        {
          "name": "state",
          "type": "string"
        },
        {
          "name": "country_iso2",
          "type": "string"
        },
        {
          "name": "post_code",
          "type": "string"
        }
      ],
      "type": "PostAddress"
    },
    {
      "id": "-1868808300",
      "predicate": "paymentRequestedInfo",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "name",
          "type": "flags.0?string"
        },
        {
          "name": "phone",
          "type": "flags.1?string"
        },
        {
          "name": "email",
          "type": "flags.2?string"
        },
        {
          "name": "shipping_address",
          "type": "flags.3?PostAddress"
        }
      ],
      "type": "PaymentRequestedInfo"
    },
    {
      "id": "-2095595325",
      "predicate": "updateBotWebhookJSON",
      "params": [
        {
          "name": "data",
          "type": "DataJSON"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-1684914010",
      "predicate": "updateBotWebhookJSONQuery",
      "params": [
        {
          "name": "query_id",
          "type": "long"
        },
        {
          "name": "data",
          "type": "DataJSON"
        },
        {
          "name": "timeout",
          "type": "int"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-523384512",
      "predicate": "updateBotShippingQuery",
      "params": [
        {
          "name": "query_id",
          "type": "long"
        },
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "payload",
          "type": "bytes"
        },
        {
          "name": "shipping_address",
          "type": "PostAddress"
        }
      ],
      "type": "Update"
    },
    {
      "id": "1563376297",
      "predicate": "updateBotPrecheckoutQuery",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "query_id",
          "type": "long"
        },
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "payload",
          "type": "bytes"
        },
        {
          "name": "info",
          "type": "flags.0?PaymentRequestedInfo"
        },
        {
          "name": "shipping_option_id",
          "type": "flags.1?string"
        },
        {
          "name": "currency",
          "type": "string"
        },
        {
          "name": "total_amount",
          "type": "long"
        }
      ],
      "type": "Update"
    },
    {
      "id": "2104790276",
      "predicate": "dataJSON",
      "params": [
        {
          "name": "data",
          "type": "string"
        }
      ],
      "type": "DataJSON"
    },
    {
      "id": "-886477832",
      "predicate": "labeledPrice",
      "params": [
        {
          "name": "label",
          "type": "string"
        },
        {
          "name": "amount",
          "type": "long"
        }
      ],
      "type": "LabeledPrice"
    },
    {
      "id": "-368917890",
      "predicate": "paymentCharge",
      "params": [
        {
          "name": "id",
          "type": "string"
        },
        {
          "name": "provider_charge_id",
          "type": "string"
        }
      ],
      "type": "PaymentCharge"
    },
    {
      "id": "-842892769",
      "predicate": "paymentSavedCredentialsCard",
      "params": [
        {
          "name": "id",
          "type": "string"
        },
        {
          "name": "title",
          "type": "string"
        }
      ],
      "type": "PaymentSavedCredentials"
    },
    {
      "id": "-971322408",
      "predicate": "webDocument",
      "params": [
        {
          "name": "url",
          "type": "string"
        },
        {
          "name": "access_hash",
          "type": "long"
        },
        {
          "name": "size",
          "type": "int"
        },
        {
          "name": "mime_type",
          "type": "string"
        },
        {
          "name": "attributes",
          "type": "Vector<DocumentAttribute>"
        },
        {
          "name": "dc_id",
          "type": "int"
        }
      ],
      "type": "WebDocument"
    },
    {
      "id": "-1678949555",
      "predicate": "inputWebDocument",
      "params": [
        {
          "name": "url",
          "type": "string"
        },
        {
          "name": "size",
          "type": "int"
        },
        {
          "name": "mime_type",
          "type": "string"
        },
        {
          "name": "attributes",
          "type": "Vector<DocumentAttribute>"
        }
      ],
      "type": "InputWebDocument"
    },
    {
      "id": "-1036396922",
      "predicate": "inputWebFileLocation",
      "params": [
        {
          "name": "url",
          "type": "string"
        },
        {
          "name": "access_hash",
          "type": "long"
        }
      ],
      "type": "InputWebFileLocation"
    },
    {
      "id": "568808380",
      "predicate": "upload.webFile",
      "params": [
        {
          "name": "size",
          "type": "int"
        },
        {
          "name": "mime_type",
          "type": "string"
        },
        {
          "name": "file_type",
          "type": "storage.FileType"
        },
        {
          "name": "mtime",
          "type": "int"
        },
        {
          "name": "bytes",
          "type": "bytes"
        }
      ],
      "type": "upload.WebFile"
    },
    {
      "id": "-784000893",
      "predicate": "payments.validatedRequestedInfo",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "id",
          "type": "flags.0?string"
        },
        {
          "name": "shipping_options",
          "type": "flags.1?Vector<ShippingOption>"
        }
      ],
      "type": "payments.ValidatedRequestedInfo"
    },
    {
      "id": "1314881805",
      "predicate": "payments.paymentResult",
      "params": [
        {
          "name": "updates",
          "type": "Updates"
        }
      ],
      "type": "payments.PaymentResult"
    },
    {
      "id": "1800845601",
      "predicate": "payments.paymentVerficationNeeded",
      "params": [
        {
          "name": "url",
          "type": "string"
        }
      ],
      "type": "payments.PaymentResult"
    },
    {
      "id": "1342771681",
      "predicate": "payments.paymentReceipt",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "bot_id",
          "type": "int"
        },
        {
          "name": "invoice",
          "type": "Invoice"
        },
        {
          "name": "provider_id",
          "type": "int"
        },
        {
          "name": "info",
          "type": "flags.0?PaymentRequestedInfo"
        },
        {
          "name": "shipping",
          "type": "flags.1?ShippingOption"
        },
        {
          "name": "currency",
          "type": "string"
        },
        {
          "name": "total_amount",
          "type": "long"
        },
        {
          "name": "credentials_title",
          "type": "string"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "payments.PaymentReceipt"
    },
    {
      "id": "-74456004",
      "predicate": "payments.savedInfo",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "has_saved_credentials",
          "type": "flags.1?true"
        },
        {
          "name": "saved_info",
          "type": "flags.0?PaymentRequestedInfo"
        }
      ],
      "type": "payments.SavedInfo"
    },
    {
      "id": "-1056001329",
      "predicate": "inputPaymentCredentialsSaved",
      "params": [
        {
          "name": "id",
          "type": "string"
        },
        {
          "name": "tmp_password",
          "type": "bytes"
        }
      ],
      "type": "InputPaymentCredentials"
    },
    {
      "id": "873977640",
      "predicate": "inputPaymentCredentials",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "save",
          "type": "flags.0?true"
        },
        {
          "name": "data",
          "type": "DataJSON"
        }
      ],
      "type": "InputPaymentCredentials"
    },
    {
      "id": "-614138572",
      "predicate": "account.tmpPassword",
      "params": [
        {
          "name": "tmp_password",
          "type": "bytes"
        },
        {
          "name": "valid_until",
          "type": "int"
        }
      ],
      "type": "account.TmpPassword"
    },
    {
      "id": "-1239335713",
      "predicate": "shippingOption",
      "params": [
        {
          "name": "id",
          "type": "string"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "prices",
          "type": "Vector<LabeledPrice>"
        }
      ],
      "type": "ShippingOption"
    },
    {
      "id": "1828732223",
      "predicate": "phoneCallAccepted",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "access_hash",
          "type": "long"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "admin_id",
          "type": "int"
        },
        {
          "name": "participant_id",
          "type": "int"
        },
        {
          "name": "g_b",
          "type": "bytes"
        },
        {
          "name": "protocol",
          "type": "PhoneCallProtocol"
        }
      ],
      "type": "PhoneCall"
    },
    {
      "id": "2054952868",
      "predicate": "inputMessagesFilterRoundVoice",
      "params": [],
      "type": "MessagesFilter"
    },
    {
      "id": "-1253451181",
      "predicate": "inputMessagesFilterRoundVideo",
      "params": [],
      "type": "MessagesFilter"
    },
    {
      "id": "-363659686",
      "predicate": "upload.fileCdnRedirect",
      "params": [
        {
          "name": "dc_id",
          "type": "int"
        },
        {
          "name": "file_token",
          "type": "bytes"
        },
        {
          "name": "encryption_key",
          "type": "bytes"
        },
        {
          "name": "encryption_iv",
          "type": "bytes"
        },
        {
          "name": "cdn_file_hashes",
          "type": "Vector<CdnFileHash>"
        }
      ],
      "type": "upload.File"
    },
    {
      "id": "-1997373508",
      "predicate": "sendMessageRecordRoundAction",
      "params": [],
      "type": "SendMessageAction"
    },
    {
      "id": "608050278",
      "predicate": "sendMessageUploadRoundAction",
      "params": [
        {
          "name": "progress",
          "type": "int"
        }
      ],
      "type": "SendMessageAction"
    },
    {
      "id": "-290921362",
      "predicate": "upload.cdnFileReuploadNeeded",
      "params": [
        {
          "name": "request_token",
          "type": "bytes"
        }
      ],
      "type": "upload.CdnFile"
    },
    {
      "id": "-1449145777",
      "predicate": "upload.cdnFile",
      "params": [
        {
          "name": "bytes",
          "type": "bytes"
        }
      ],
      "type": "upload.CdnFile"
    },
    {
      "id": "-914167110",
      "predicate": "cdnPublicKey",
      "params": [
        {
          "name": "dc_id",
          "type": "int"
        },
        {
          "name": "public_key",
          "type": "string"
        }
      ],
      "type": "CdnPublicKey"
    },
    {
      "id": "1462101002",
      "predicate": "cdnConfig",
      "params": [
        {
          "name": "public_keys",
          "type": "Vector<CdnPublicKey>"
        }
      ],
      "type": "CdnConfig"
    },
    {
      "id": "281165899",
      "predicate": "updateLangPackTooLong",
      "params": [],
      "type": "Update"
    },
    {
      "id": "1442983757",
      "predicate": "updateLangPack",
      "params": [
        {
          "name": "difference",
          "type": "LangPackDifference"
        }
      ],
      "type": "Update"
    },
    {
      "id": "-283684427",
      "predicate": "pageBlockChannel",
      "params": [
        {
          "name": "channel",
          "type": "Chat"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "-6249322",
      "predicate": "inputStickerSetItem",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "document",
          "type": "InputDocument"
        },
        {
          "name": "emoji",
          "type": "string"
        },
        {
          "name": "mask_coords",
          "type": "flags.0?MaskCoords"
        }
      ],
      "type": "InputStickerSetItem"
    },
    {
      "id": "-892239370",
      "predicate": "langPackString",
      "params": [
        {
          "name": "key",
          "type": "string"
        },
        {
          "name": "value",
          "type": "string"
        }
      ],
      "type": "LangPackString"
    },
    {
      "id": "1816636575",
      "predicate": "langPackStringPluralized",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "key",
          "type": "string"
        },
        {
          "name": "zero_value",
          "type": "flags.0?string"
        },
        {
          "name": "one_value",
          "type": "flags.1?string"
        },
        {
          "name": "two_value",
          "type": "flags.2?string"
        },
        {
          "name": "few_value",
          "type": "flags.3?string"
        },
        {
          "name": "many_value",
          "type": "flags.4?string"
        },
        {
          "name": "other_value",
          "type": "string"
        }
      ],
      "type": "LangPackString"
    },
    {
      "id": "695856818",
      "predicate": "langPackStringDeleted",
      "params": [
        {
          "name": "key",
          "type": "string"
        }
      ],
      "type": "LangPackString"
    },
    {
      "id": "-209337866",
      "predicate": "langPackDifference",
      "params": [
        {
          "name": "lang_code",
          "type": "string"
        },
        {
          "name": "from_version",
          "type": "int"
        },
        {
          "name": "version",
          "type": "int"
        },
        {
          "name": "strings",
          "type": "Vector<LangPackString>"
        }
      ],
      "type": "LangPackDifference"
    },
    {
      "id": "292985073",
      "predicate": "langPackLanguage",
      "params": [
        {
          "name": "name",
          "type": "string"
        },
        {
          "name": "native_name",
          "type": "string"
        },
        {
          "name": "lang_code",
          "type": "string"
        }
      ],
      "type": "LangPackLanguage"
    },
    {
      "id": "-1473271656",
      "predicate": "channelParticipantAdmin",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "can_edit",
          "type": "flags.0?true"
        },
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "inviter_id",
          "type": "int"
        },
        {
          "name": "promoted_by",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "admin_rights",
          "type": "ChannelAdminRights"
        }
      ],
      "type": "ChannelParticipant"
    },
    {
      "id": "573315206",
      "predicate": "channelParticipantBanned",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "left",
          "type": "flags.0?true"
        },
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "kicked_by",
          "type": "int"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "banned_rights",
          "type": "ChannelBannedRights"
        }
      ],
      "type": "ChannelParticipant"
    },
    {
      "id": "338142689",
      "predicate": "channelParticipantsBanned",
      "params": [
        {
          "name": "q",
          "type": "string"
        }
      ],
      "type": "ChannelParticipantsFilter"
    },
    {
      "id": "106343499",
      "predicate": "channelParticipantsSearch",
      "params": [
        {
          "name": "q",
          "type": "string"
        }
      ],
      "type": "ChannelParticipantsFilter"
    },
    {
      "id": "511092620",
      "predicate": "topPeerCategoryPhoneCalls",
      "params": [],
      "type": "TopPeerCategory"
    },
    {
      "id": "834148991",
      "predicate": "pageBlockAudio",
      "params": [
        {
          "name": "audio_id",
          "type": "long"
        },
        {
          "name": "caption",
          "type": "RichText"
        }
      ],
      "type": "PageBlock"
    },
    {
      "id": "1568467877",
      "predicate": "channelAdminRights",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "change_info",
          "type": "flags.0?true"
        },
        {
          "name": "post_messages",
          "type": "flags.1?true"
        },
        {
          "name": "edit_messages",
          "type": "flags.2?true"
        },
        {
          "name": "delete_messages",
          "type": "flags.3?true"
        },
        {
          "name": "ban_users",
          "type": "flags.4?true"
        },
        {
          "name": "invite_users",
          "type": "flags.5?true"
        },
        {
          "name": "invite_link",
          "type": "flags.6?true"
        },
        {
          "name": "pin_messages",
          "type": "flags.7?true"
        },
        {
          "name": "add_admins",
          "type": "flags.9?true"
        }
      ],
      "type": "ChannelAdminRights"
    },
    {
      "id": "1489977929",
      "predicate": "channelBannedRights",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "view_messages",
          "type": "flags.0?true"
        },
        {
          "name": "send_messages",
          "type": "flags.1?true"
        },
        {
          "name": "send_media",
          "type": "flags.2?true"
        },
        {
          "name": "send_stickers",
          "type": "flags.3?true"
        },
        {
          "name": "send_gifs",
          "type": "flags.4?true"
        },
        {
          "name": "send_games",
          "type": "flags.5?true"
        },
        {
          "name": "send_inline",
          "type": "flags.6?true"
        },
        {
          "name": "embed_links",
          "type": "flags.7?true"
        },
        {
          "name": "until_date",
          "type": "int"
        }
      ],
      "type": "ChannelBannedRights"
    },
    {
      "id": "-421545947",
      "predicate": "channelAdminLogEventActionChangeTitle",
      "params": [
        {
          "name": "prev_value",
          "type": "string"
        },
        {
          "name": "new_value",
          "type": "string"
        }
      ],
      "type": "ChannelAdminLogEventAction"
    },
    {
      "id": "1427671598",
      "predicate": "channelAdminLogEventActionChangeAbout",
      "params": [
        {
          "name": "prev_value",
          "type": "string"
        },
        {
          "name": "new_value",
          "type": "string"
        }
      ],
      "type": "ChannelAdminLogEventAction"
    },
    {
      "id": "1783299128",
      "predicate": "channelAdminLogEventActionChangeUsername",
      "params": [
        {
          "name": "prev_value",
          "type": "string"
        },
        {
          "name": "new_value",
          "type": "string"
        }
      ],
      "type": "ChannelAdminLogEventAction"
    },
    {
      "id": "-1204857405",
      "predicate": "channelAdminLogEventActionChangePhoto",
      "params": [
        {
          "name": "prev_photo",
          "type": "ChatPhoto"
        },
        {
          "name": "new_photo",
          "type": "ChatPhoto"
        }
      ],
      "type": "ChannelAdminLogEventAction"
    },
    {
      "id": "460916654",
      "predicate": "channelAdminLogEventActionToggleInvites",
      "params": [
        {
          "name": "new_value",
          "type": "Bool"
        }
      ],
      "type": "ChannelAdminLogEventAction"
    },
    {
      "id": "648939889",
      "predicate": "channelAdminLogEventActionToggleSignatures",
      "params": [
        {
          "name": "new_value",
          "type": "Bool"
        }
      ],
      "type": "ChannelAdminLogEventAction"
    },
    {
      "id": "-370660328",
      "predicate": "channelAdminLogEventActionUpdatePinned",
      "params": [
        {
          "name": "message",
          "type": "Message"
        }
      ],
      "type": "ChannelAdminLogEventAction"
    },
    {
      "id": "1889215493",
      "predicate": "channelAdminLogEventActionEditMessage",
      "params": [
        {
          "name": "prev_message",
          "type": "Message"
        },
        {
          "name": "new_message",
          "type": "Message"
        }
      ],
      "type": "ChannelAdminLogEventAction"
    },
    {
      "id": "1121994683",
      "predicate": "channelAdminLogEventActionDeleteMessage",
      "params": [
        {
          "name": "message",
          "type": "Message"
        }
      ],
      "type": "ChannelAdminLogEventAction"
    },
    {
      "id": "405815507",
      "predicate": "channelAdminLogEventActionParticipantJoin",
      "params": [],
      "type": "ChannelAdminLogEventAction"
    },
    {
      "id": "-124291086",
      "predicate": "channelAdminLogEventActionParticipantLeave",
      "params": [],
      "type": "ChannelAdminLogEventAction"
    },
    {
      "id": "-484690728",
      "predicate": "channelAdminLogEventActionParticipantInvite",
      "params": [
        {
          "name": "participant",
          "type": "ChannelParticipant"
        }
      ],
      "type": "ChannelAdminLogEventAction"
    },
    {
      "id": "-422036098",
      "predicate": "channelAdminLogEventActionParticipantToggleBan",
      "params": [
        {
          "name": "prev_participant",
          "type": "ChannelParticipant"
        },
        {
          "name": "new_participant",
          "type": "ChannelParticipant"
        }
      ],
      "type": "ChannelAdminLogEventAction"
    },
    {
      "id": "-714643696",
      "predicate": "channelAdminLogEventActionParticipantToggleAdmin",
      "params": [
        {
          "name": "prev_participant",
          "type": "ChannelParticipant"
        },
        {
          "name": "new_participant",
          "type": "ChannelParticipant"
        }
      ],
      "type": "ChannelAdminLogEventAction"
    },
    {
      "id": "995769920",
      "predicate": "channelAdminLogEvent",
      "params": [
        {
          "name": "id",
          "type": "long"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "user_id",
          "type": "int"
        },
        {
          "name": "action",
          "type": "ChannelAdminLogEventAction"
        }
      ],
      "type": "ChannelAdminLogEvent"
    },
    {
      "id": "-309659827",
      "predicate": "channels.adminLogResults",
      "params": [
        {
          "name": "events",
          "type": "Vector<ChannelAdminLogEvent>"
        },
        {
          "name": "chats",
          "type": "Vector<Chat>"
        },
        {
          "name": "users",
          "type": "Vector<User>"
        }
      ],
      "type": "channels.AdminLogResults"
    },
    {
      "id": "-368018716",
      "predicate": "channelAdminLogEventsFilter",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "join",
          "type": "flags.0?true"
        },
        {
          "name": "leave",
          "type": "flags.1?true"
        },
        {
          "name": "invite",
          "type": "flags.2?true"
        },
        {
          "name": "ban",
          "type": "flags.3?true"
        },
        {
          "name": "unban",
          "type": "flags.4?true"
        },
        {
          "name": "kick",
          "type": "flags.5?true"
        },
        {
          "name": "unkick",
          "type": "flags.6?true"
        },
        {
          "name": "promote",
          "type": "flags.7?true"
        },
        {
          "name": "demote",
          "type": "flags.8?true"
        },
        {
          "name": "info",
          "type": "flags.9?true"
        },
        {
          "name": "settings",
          "type": "flags.10?true"
        },
        {
          "name": "pinned",
          "type": "flags.11?true"
        },
        {
          "name": "edit",
          "type": "flags.12?true"
        },
        {
          "name": "delete",
          "type": "flags.13?true"
        }
      ],
      "type": "ChannelAdminLogEventsFilter"
    },
    {
      "id": "1200788123",
      "predicate": "messageActionScreenshotTaken",
      "params": [],
      "type": "MessageAction"
    },
    {
      "id": "1558266229",
      "predicate": "popularContact",
      "params": [
        {
          "name": "client_id",
          "type": "long"
        },
        {
          "name": "importers",
          "type": "int"
        }
      ],
      "type": "PopularContact"
    },
    {
      "id": "2012136335",
      "predicate": "cdnFileHash",
      "params": [
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "limit",
          "type": "int"
        },
        {
          "name": "hash",
          "type": "bytes"
        }
      ],
      "type": "CdnFileHash"
    },
    {
      "id": "-1040652646",
      "predicate": "inputMessagesFilterMyMentions",
      "params": [],
      "type": "MessagesFilter"
    },
    {
      "id": "1187706024",
      "predicate": "inputMessagesFilterMyMentionsUnread",
      "params": [],
      "type": "MessagesFilter"
    },
    {
      "id": "1887741886",
      "predicate": "updateContactsReset",
      "params": [],
      "type": "Update"
    },
    {
      "id": "-1312568665",
      "predicate": "channelAdminLogEventActionChangeStickerSet",
      "params": [
        {
          "name": "prev_stickerset",
          "type": "InputStickerSet"
        },
        {
          "name": "new_stickerset",
          "type": "InputStickerSet"
        }
      ],
      "type": "ChannelAdminLogEventAction"
    },
    {
      "id": "-451831443",
      "predicate": "updateFavedStickers",
      "params": [],
      "type": "Update"
    },
    {
      "id": "-209768682",
      "predicate": "messages.favedStickers",
      "params": [
        {
          "name": "hash",
          "type": "int"
        },
        {
          "name": "packs",
          "type": "Vector<StickerPack>"
        },
        {
          "name": "stickers",
          "type": "Vector<Document>"
        }
      ],
      "type": "messages.FavedStickers"
    },
    {
      "id": "-1634752813",
      "predicate": "messages.favedStickersNotModified",
      "params": [],
      "type": "messages.FavedStickers"
    },
    {
      "id": "-1987495099",
      "predicate": "updateChannelReadMessagesContents",
      "params": [
        {
          "name": "channel_id",
          "type": "int"
        },
        {
          "name": "messages",
          "type": "Vector<int>"
        }
      ],
      "type": "Update"
    }
  ],
  "methods": [
    {
      "id": "-878758099",
      "method": "invokeAfterMsg",
      "params": [
        {
          "name": "msg_id",
          "type": "long"
        },
        {
          "name": "query",
          "type": "!X"
        }
      ],
      "type": "X"
    },
    {
      "id": "1036301552",
      "method": "invokeAfterMsgs",
      "params": [
        {
          "name": "msg_ids",
          "type": "Vector<long>"
        },
        {
          "name": "query",
          "type": "!X"
        }
      ],
      "type": "X"
    },
    {
      "id": "1877286395",
      "method": "auth.checkPhone",
      "params": [
        {
          "name": "phone_number",
          "type": "string"
        }
      ],
      "type": "auth.CheckedPhone"
    },
    {
      "id": "-2035355412",
      "method": "auth.sendCode",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "allow_flashcall",
          "type": "flags.0?true"
        },
        {
          "name": "phone_number",
          "type": "string"
        },
        {
          "name": "current_number",
          "type": "flags.0?Bool"
        },
        {
          "name": "api_id",
          "type": "int"
        },
        {
          "name": "api_hash",
          "type": "string"
        }
      ],
      "type": "auth.SentCode"
    },
    {
      "id": "453408308",
      "method": "auth.signUp",
      "params": [
        {
          "name": "phone_number",
          "type": "string"
        },
        {
          "name": "phone_code_hash",
          "type": "string"
        },
        {
          "name": "phone_code",
          "type": "string"
        },
        {
          "name": "first_name",
          "type": "string"
        },
        {
          "name": "last_name",
          "type": "string"
        }
      ],
      "type": "auth.Authorization"
    },
    {
      "id": "-1126886015",
      "method": "auth.signIn",
      "params": [
        {
          "name": "phone_number",
          "type": "string"
        },
        {
          "name": "phone_code_hash",
          "type": "string"
        },
        {
          "name": "phone_code",
          "type": "string"
        }
      ],
      "type": "auth.Authorization"
    },
    {
      "id": "1461180992",
      "method": "auth.logOut",
      "params": [],
      "type": "Bool"
    },
    {
      "id": "-1616179942",
      "method": "auth.resetAuthorizations",
      "params": [],
      "type": "Bool"
    },
    {
      "id": "1998331287",
      "method": "auth.sendInvites",
      "params": [
        {
          "name": "phone_numbers",
          "type": "Vector<string>"
        },
        {
          "name": "message",
          "type": "string"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-440401971",
      "method": "auth.exportAuthorization",
      "params": [
        {
          "name": "dc_id",
          "type": "int"
        }
      ],
      "type": "auth.ExportedAuthorization"
    },
    {
      "id": "-470837741",
      "method": "auth.importAuthorization",
      "params": [
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "bytes",
          "type": "bytes"
        }
      ],
      "type": "auth.Authorization"
    },
    {
      "id": "1669245048",
      "method": "account.registerDevice",
      "params": [
        {
          "name": "token_type",
          "type": "int"
        },
        {
          "name": "token",
          "type": "string"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "1707432768",
      "method": "account.unregisterDevice",
      "params": [
        {
          "name": "token_type",
          "type": "int"
        },
        {
          "name": "token",
          "type": "string"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-2067899501",
      "method": "account.updateNotifySettings",
      "params": [
        {
          "name": "peer",
          "type": "InputNotifyPeer"
        },
        {
          "name": "settings",
          "type": "InputPeerNotifySettings"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "313765169",
      "method": "account.getNotifySettings",
      "params": [
        {
          "name": "peer",
          "type": "InputNotifyPeer"
        }
      ],
      "type": "PeerNotifySettings"
    },
    {
      "id": "-612493497",
      "method": "account.resetNotifySettings",
      "params": [],
      "type": "Bool"
    },
    {
      "id": "2018596725",
      "method": "account.updateProfile",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "first_name",
          "type": "flags.0?string"
        },
        {
          "name": "last_name",
          "type": "flags.1?string"
        },
        {
          "name": "about",
          "type": "flags.2?string"
        }
      ],
      "type": "User"
    },
    {
      "id": "1713919532",
      "method": "account.updateStatus",
      "params": [
        {
          "name": "offline",
          "type": "Bool"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-1068696894",
      "method": "account.getWallPapers",
      "params": [],
      "type": "Vector<WallPaper>"
    },
    {
      "id": "227648840",
      "method": "users.getUsers",
      "params": [
        {
          "name": "id",
          "type": "Vector<InputUser>"
        }
      ],
      "type": "Vector<User>"
    },
    {
      "id": "-902781519",
      "method": "users.getFullUser",
      "params": [
        {
          "name": "id",
          "type": "InputUser"
        }
      ],
      "type": "UserFull"
    },
    {
      "id": "-995929106",
      "method": "contacts.getStatuses",
      "params": [],
      "type": "Vector<ContactStatus>"
    },
    {
      "id": "-1071414113",
      "method": "contacts.getContacts",
      "params": [
        {
          "name": "hash",
          "type": "int"
        }
      ],
      "type": "contacts.Contacts"
    },
    {
      "id": "746589157",
      "method": "contacts.importContacts",
      "params": [
        {
          "name": "contacts",
          "type": "Vector<InputContact>"
        }
      ],
      "type": "contacts.ImportedContacts"
    },
    {
      "id": "301470424",
      "method": "contacts.search",
      "params": [
        {
          "name": "q",
          "type": "string"
        },
        {
          "name": "limit",
          "type": "int"
        }
      ],
      "type": "contacts.Found"
    },
    {
      "id": "-1902823612",
      "method": "contacts.deleteContact",
      "params": [
        {
          "name": "id",
          "type": "InputUser"
        }
      ],
      "type": "contacts.Link"
    },
    {
      "id": "1504393374",
      "method": "contacts.deleteContacts",
      "params": [
        {
          "name": "id",
          "type": "Vector<InputUser>"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "858475004",
      "method": "contacts.block",
      "params": [
        {
          "name": "id",
          "type": "InputUser"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-448724803",
      "method": "contacts.unblock",
      "params": [
        {
          "name": "id",
          "type": "InputUser"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-176409329",
      "method": "contacts.getBlocked",
      "params": [
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "limit",
          "type": "int"
        }
      ],
      "type": "contacts.Blocked"
    },
    {
      "id": "1109588596",
      "method": "messages.getMessages",
      "params": [
        {
          "name": "id",
          "type": "Vector<int>"
        }
      ],
      "type": "messages.Messages"
    },
    {
      "id": "421243333",
      "method": "messages.getDialogs",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "exclude_pinned",
          "type": "flags.0?true"
        },
        {
          "name": "offset_date",
          "type": "int"
        },
        {
          "name": "offset_id",
          "type": "int"
        },
        {
          "name": "offset_peer",
          "type": "InputPeer"
        },
        {
          "name": "limit",
          "type": "int"
        }
      ],
      "type": "messages.Dialogs"
    },
    {
      "id": "-1347868602",
      "method": "messages.getHistory",
      "params": [
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "offset_id",
          "type": "int"
        },
        {
          "name": "offset_date",
          "type": "int"
        },
        {
          "name": "add_offset",
          "type": "int"
        },
        {
          "name": "limit",
          "type": "int"
        },
        {
          "name": "max_id",
          "type": "int"
        },
        {
          "name": "min_id",
          "type": "int"
        }
      ],
      "type": "messages.Messages"
    },
    {
      "id": "60726944",
      "method": "messages.search",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "q",
          "type": "string"
        },
        {
          "name": "from_id",
          "type": "flags.0?InputUser"
        },
        {
          "name": "filter",
          "type": "MessagesFilter"
        },
        {
          "name": "min_date",
          "type": "int"
        },
        {
          "name": "max_date",
          "type": "int"
        },
        {
          "name": "offset_id",
          "type": "int"
        },
        {
          "name": "add_offset",
          "type": "int"
        },
        {
          "name": "limit",
          "type": "int"
        },
        {
          "name": "max_id",
          "type": "int"
        },
        {
          "name": "min_id",
          "type": "int"
        }
      ],
      "type": "messages.Messages"
    },
    {
      "id": "238054714",
      "method": "messages.readHistory",
      "params": [
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "max_id",
          "type": "int"
        }
      ],
      "type": "messages.AffectedMessages"
    },
    {
      "id": "469850889",
      "method": "messages.deleteHistory",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "just_clear",
          "type": "flags.0?true"
        },
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "max_id",
          "type": "int"
        }
      ],
      "type": "messages.AffectedHistory"
    },
    {
      "id": "-443640366",
      "method": "messages.deleteMessages",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "revoke",
          "type": "flags.0?true"
        },
        {
          "name": "id",
          "type": "Vector<int>"
        }
      ],
      "type": "messages.AffectedMessages"
    },
    {
      "id": "94983360",
      "method": "messages.receivedMessages",
      "params": [
        {
          "name": "max_id",
          "type": "int"
        }
      ],
      "type": "Vector<ReceivedNotifyMessage>"
    },
    {
      "id": "-1551737264",
      "method": "messages.setTyping",
      "params": [
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "action",
          "type": "SendMessageAction"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-91733382",
      "method": "messages.sendMessage",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "no_webpage",
          "type": "flags.1?true"
        },
        {
          "name": "silent",
          "type": "flags.5?true"
        },
        {
          "name": "background",
          "type": "flags.6?true"
        },
        {
          "name": "clear_draft",
          "type": "flags.7?true"
        },
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "reply_to_msg_id",
          "type": "flags.0?int"
        },
        {
          "name": "message",
          "type": "string"
        },
        {
          "name": "random_id",
          "type": "long"
        },
        {
          "name": "reply_markup",
          "type": "flags.2?ReplyMarkup"
        },
        {
          "name": "entities",
          "type": "flags.3?Vector<MessageEntity>"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-923703407",
      "method": "messages.sendMedia",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "silent",
          "type": "flags.5?true"
        },
        {
          "name": "background",
          "type": "flags.6?true"
        },
        {
          "name": "clear_draft",
          "type": "flags.7?true"
        },
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "reply_to_msg_id",
          "type": "flags.0?int"
        },
        {
          "name": "media",
          "type": "InputMedia"
        },
        {
          "name": "random_id",
          "type": "long"
        },
        {
          "name": "reply_markup",
          "type": "flags.2?ReplyMarkup"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "1888354709",
      "method": "messages.forwardMessages",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "silent",
          "type": "flags.5?true"
        },
        {
          "name": "background",
          "type": "flags.6?true"
        },
        {
          "name": "with_my_score",
          "type": "flags.8?true"
        },
        {
          "name": "from_peer",
          "type": "InputPeer"
        },
        {
          "name": "id",
          "type": "Vector<int>"
        },
        {
          "name": "random_id",
          "type": "Vector<long>"
        },
        {
          "name": "to_peer",
          "type": "InputPeer"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "1013621127",
      "method": "messages.getChats",
      "params": [
        {
          "name": "id",
          "type": "Vector<int>"
        }
      ],
      "type": "messages.Chats"
    },
    {
      "id": "998448230",
      "method": "messages.getFullChat",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        }
      ],
      "type": "messages.ChatFull"
    },
    {
      "id": "-599447467",
      "method": "messages.editChatTitle",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "title",
          "type": "string"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-900957736",
      "method": "messages.editChatPhoto",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "photo",
          "type": "InputChatPhoto"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-106911223",
      "method": "messages.addChatUser",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "user_id",
          "type": "InputUser"
        },
        {
          "name": "fwd_limit",
          "type": "int"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-530505962",
      "method": "messages.deleteChatUser",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "user_id",
          "type": "InputUser"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "164303470",
      "method": "messages.createChat",
      "params": [
        {
          "name": "users",
          "type": "Vector<InputUser>"
        },
        {
          "name": "title",
          "type": "string"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-304838614",
      "method": "updates.getState",
      "params": [],
      "type": "updates.State"
    },
    {
      "id": "630429265",
      "method": "updates.getDifference",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "pts_total_limit",
          "type": "flags.0?int"
        },
        {
          "name": "date",
          "type": "int"
        },
        {
          "name": "qts",
          "type": "int"
        }
      ],
      "type": "updates.Difference"
    },
    {
      "id": "-256159406",
      "method": "photos.updateProfilePhoto",
      "params": [
        {
          "name": "id",
          "type": "InputPhoto"
        }
      ],
      "type": "UserProfilePhoto"
    },
    {
      "id": "1328726168",
      "method": "photos.uploadProfilePhoto",
      "params": [
        {
          "name": "file",
          "type": "InputFile"
        }
      ],
      "type": "photos.Photo"
    },
    {
      "id": "-1291540959",
      "method": "upload.saveFilePart",
      "params": [
        {
          "name": "file_id",
          "type": "long"
        },
        {
          "name": "file_part",
          "type": "int"
        },
        {
          "name": "bytes",
          "type": "bytes"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-475607115",
      "method": "upload.getFile",
      "params": [
        {
          "name": "location",
          "type": "InputFileLocation"
        },
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "limit",
          "type": "int"
        }
      ],
      "type": "upload.File"
    },
    {
      "id": "-990308245",
      "method": "help.getConfig",
      "params": [],
      "type": "Config"
    },
    {
      "id": "531836966",
      "method": "help.getNearestDc",
      "params": [],
      "type": "NearestDc"
    },
    {
      "id": "-1372724842",
      "method": "help.getAppUpdate",
      "params": [],
      "type": "help.AppUpdate"
    },
    {
      "id": "1862465352",
      "method": "help.saveAppLog",
      "params": [
        {
          "name": "events",
          "type": "Vector<InputAppEvent>"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "1295590211",
      "method": "help.getInviteText",
      "params": [],
      "type": "help.InviteText"
    },
    {
      "id": "-2016444625",
      "method": "photos.deletePhotos",
      "params": [
        {
          "name": "id",
          "type": "Vector<InputPhoto>"
        }
      ],
      "type": "Vector<long>"
    },
    {
      "id": "-1848823128",
      "method": "photos.getUserPhotos",
      "params": [
        {
          "name": "user_id",
          "type": "InputUser"
        },
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "max_id",
          "type": "long"
        },
        {
          "name": "limit",
          "type": "int"
        }
      ],
      "type": "photos.Photos"
    },
    {
      "id": "865483769",
      "method": "messages.forwardMessage",
      "params": [
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "random_id",
          "type": "long"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "651135312",
      "method": "messages.getDhConfig",
      "params": [
        {
          "name": "version",
          "type": "int"
        },
        {
          "name": "random_length",
          "type": "int"
        }
      ],
      "type": "messages.DhConfig"
    },
    {
      "id": "-162681021",
      "method": "messages.requestEncryption",
      "params": [
        {
          "name": "user_id",
          "type": "InputUser"
        },
        {
          "name": "random_id",
          "type": "int"
        },
        {
          "name": "g_a",
          "type": "bytes"
        }
      ],
      "type": "EncryptedChat"
    },
    {
      "id": "1035731989",
      "method": "messages.acceptEncryption",
      "params": [
        {
          "name": "peer",
          "type": "InputEncryptedChat"
        },
        {
          "name": "g_b",
          "type": "bytes"
        },
        {
          "name": "key_fingerprint",
          "type": "long"
        }
      ],
      "type": "EncryptedChat"
    },
    {
      "id": "-304536635",
      "method": "messages.discardEncryption",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "2031374829",
      "method": "messages.setEncryptedTyping",
      "params": [
        {
          "name": "peer",
          "type": "InputEncryptedChat"
        },
        {
          "name": "typing",
          "type": "Bool"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "2135648522",
      "method": "messages.readEncryptedHistory",
      "params": [
        {
          "name": "peer",
          "type": "InputEncryptedChat"
        },
        {
          "name": "max_date",
          "type": "int"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-1451792525",
      "method": "messages.sendEncrypted",
      "params": [
        {
          "name": "peer",
          "type": "InputEncryptedChat"
        },
        {
          "name": "random_id",
          "type": "long"
        },
        {
          "name": "data",
          "type": "bytes"
        }
      ],
      "type": "messages.SentEncryptedMessage"
    },
    {
      "id": "-1701831834",
      "method": "messages.sendEncryptedFile",
      "params": [
        {
          "name": "peer",
          "type": "InputEncryptedChat"
        },
        {
          "name": "random_id",
          "type": "long"
        },
        {
          "name": "data",
          "type": "bytes"
        },
        {
          "name": "file",
          "type": "InputEncryptedFile"
        }
      ],
      "type": "messages.SentEncryptedMessage"
    },
    {
      "id": "852769188",
      "method": "messages.sendEncryptedService",
      "params": [
        {
          "name": "peer",
          "type": "InputEncryptedChat"
        },
        {
          "name": "random_id",
          "type": "long"
        },
        {
          "name": "data",
          "type": "bytes"
        }
      ],
      "type": "messages.SentEncryptedMessage"
    },
    {
      "id": "1436924774",
      "method": "messages.receivedQueue",
      "params": [
        {
          "name": "max_qts",
          "type": "int"
        }
      ],
      "type": "Vector<long>"
    },
    {
      "id": "-562337987",
      "method": "upload.saveBigFilePart",
      "params": [
        {
          "name": "file_id",
          "type": "long"
        },
        {
          "name": "file_part",
          "type": "int"
        },
        {
          "name": "file_total_parts",
          "type": "int"
        },
        {
          "name": "bytes",
          "type": "bytes"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-951575130",
      "method": "initConnection",
      "params": [
        {
          "name": "api_id",
          "type": "int"
        },
        {
          "name": "device_model",
          "type": "string"
        },
        {
          "name": "system_version",
          "type": "string"
        },
        {
          "name": "app_version",
          "type": "string"
        },
        {
          "name": "system_lang_code",
          "type": "string"
        },
        {
          "name": "lang_pack",
          "type": "string"
        },
        {
          "name": "lang_code",
          "type": "string"
        },
        {
          "name": "query",
          "type": "!X"
        }
      ],
      "type": "X"
    },
    {
      "id": "-1663104819",
      "method": "help.getSupport",
      "params": [],
      "type": "help.Support"
    },
    {
      "id": "-841733627",
      "method": "auth.bindTempAuthKey",
      "params": [
        {
          "name": "perm_auth_key_id",
          "type": "long"
        },
        {
          "name": "nonce",
          "type": "long"
        },
        {
          "name": "expires_at",
          "type": "int"
        },
        {
          "name": "encrypted_message",
          "type": "bytes"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-2065352905",
      "method": "contacts.exportCard",
      "params": [],
      "type": "Vector<int>"
    },
    {
      "id": "1340184318",
      "method": "contacts.importCard",
      "params": [
        {
          "name": "export_card",
          "type": "Vector<int>"
        }
      ],
      "type": "User"
    },
    {
      "id": "916930423",
      "method": "messages.readMessageContents",
      "params": [
        {
          "name": "id",
          "type": "Vector<int>"
        }
      ],
      "type": "messages.AffectedMessages"
    },
    {
      "id": "655677548",
      "method": "account.checkUsername",
      "params": [
        {
          "name": "username",
          "type": "string"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "1040964988",
      "method": "account.updateUsername",
      "params": [
        {
          "name": "username",
          "type": "string"
        }
      ],
      "type": "User"
    },
    {
      "id": "-623130288",
      "method": "account.getPrivacy",
      "params": [
        {
          "name": "key",
          "type": "InputPrivacyKey"
        }
      ],
      "type": "account.PrivacyRules"
    },
    {
      "id": "-906486552",
      "method": "account.setPrivacy",
      "params": [
        {
          "name": "key",
          "type": "InputPrivacyKey"
        },
        {
          "name": "rules",
          "type": "Vector<InputPrivacyRule>"
        }
      ],
      "type": "account.PrivacyRules"
    },
    {
      "id": "1099779595",
      "method": "account.deleteAccount",
      "params": [
        {
          "name": "reason",
          "type": "string"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "150761757",
      "method": "account.getAccountTTL",
      "params": [],
      "type": "AccountDaysTTL"
    },
    {
      "id": "608323678",
      "method": "account.setAccountTTL",
      "params": [
        {
          "name": "ttl",
          "type": "AccountDaysTTL"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-627372787",
      "method": "invokeWithLayer",
      "params": [
        {
          "name": "layer",
          "type": "int"
        },
        {
          "name": "query",
          "type": "!X"
        }
      ],
      "type": "X"
    },
    {
      "id": "-113456221",
      "method": "contacts.resolveUsername",
      "params": [
        {
          "name": "username",
          "type": "string"
        }
      ],
      "type": "contacts.ResolvedPeer"
    },
    {
      "id": "149257707",
      "method": "account.sendChangePhoneCode",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "allow_flashcall",
          "type": "flags.0?true"
        },
        {
          "name": "phone_number",
          "type": "string"
        },
        {
          "name": "current_number",
          "type": "flags.0?Bool"
        }
      ],
      "type": "auth.SentCode"
    },
    {
      "id": "1891839707",
      "method": "account.changePhone",
      "params": [
        {
          "name": "phone_number",
          "type": "string"
        },
        {
          "name": "phone_code_hash",
          "type": "string"
        },
        {
          "name": "phone_code",
          "type": "string"
        }
      ],
      "type": "User"
    },
    {
      "id": "479598769",
      "method": "messages.getAllStickers",
      "params": [
        {
          "name": "hash",
          "type": "int"
        }
      ],
      "type": "messages.AllStickers"
    },
    {
      "id": "954152242",
      "method": "account.updateDeviceLocked",
      "params": [
        {
          "name": "period",
          "type": "int"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "1418342645",
      "method": "account.getPassword",
      "params": [],
      "type": "account.Password"
    },
    {
      "id": "174260510",
      "method": "auth.checkPassword",
      "params": [
        {
          "name": "password_hash",
          "type": "bytes"
        }
      ],
      "type": "auth.Authorization"
    },
    {
      "id": "623001124",
      "method": "messages.getWebPagePreview",
      "params": [
        {
          "name": "message",
          "type": "string"
        }
      ],
      "type": "MessageMedia"
    },
    {
      "id": "-484392616",
      "method": "account.getAuthorizations",
      "params": [],
      "type": "account.Authorizations"
    },
    {
      "id": "-545786948",
      "method": "account.resetAuthorization",
      "params": [
        {
          "name": "hash",
          "type": "long"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-1131605573",
      "method": "account.getPasswordSettings",
      "params": [
        {
          "name": "current_password_hash",
          "type": "bytes"
        }
      ],
      "type": "account.PasswordSettings"
    },
    {
      "id": "-92517498",
      "method": "account.updatePasswordSettings",
      "params": [
        {
          "name": "current_password_hash",
          "type": "bytes"
        },
        {
          "name": "new_settings",
          "type": "account.PasswordInputSettings"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-661144474",
      "method": "auth.requestPasswordRecovery",
      "params": [],
      "type": "auth.PasswordRecovery"
    },
    {
      "id": "1319464594",
      "method": "auth.recoverPassword",
      "params": [
        {
          "name": "code",
          "type": "string"
        }
      ],
      "type": "auth.Authorization"
    },
    {
      "id": "-1080796745",
      "method": "invokeWithoutUpdates",
      "params": [
        {
          "name": "query",
          "type": "!X"
        }
      ],
      "type": "X"
    },
    {
      "id": "2106086025",
      "method": "messages.exportChatInvite",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        }
      ],
      "type": "ExportedChatInvite"
    },
    {
      "id": "1051570619",
      "method": "messages.checkChatInvite",
      "params": [
        {
          "name": "hash",
          "type": "string"
        }
      ],
      "type": "ChatInvite"
    },
    {
      "id": "1817183516",
      "method": "messages.importChatInvite",
      "params": [
        {
          "name": "hash",
          "type": "string"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "639215886",
      "method": "messages.getStickerSet",
      "params": [
        {
          "name": "stickerset",
          "type": "InputStickerSet"
        }
      ],
      "type": "messages.StickerSet"
    },
    {
      "id": "-946871200",
      "method": "messages.installStickerSet",
      "params": [
        {
          "name": "stickerset",
          "type": "InputStickerSet"
        },
        {
          "name": "archived",
          "type": "Bool"
        }
      ],
      "type": "messages.StickerSetInstallResult"
    },
    {
      "id": "-110209570",
      "method": "messages.uninstallStickerSet",
      "params": [
        {
          "name": "stickerset",
          "type": "InputStickerSet"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "1738800940",
      "method": "auth.importBotAuthorization",
      "params": [
        {
          "name": "flags",
          "type": "int"
        },
        {
          "name": "api_id",
          "type": "int"
        },
        {
          "name": "api_hash",
          "type": "string"
        },
        {
          "name": "bot_auth_token",
          "type": "string"
        }
      ],
      "type": "auth.Authorization"
    },
    {
      "id": "-421563528",
      "method": "messages.startBot",
      "params": [
        {
          "name": "bot",
          "type": "InputUser"
        },
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "random_id",
          "type": "long"
        },
        {
          "name": "start_param",
          "type": "string"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-1877938321",
      "method": "help.getAppChangelog",
      "params": [
        {
          "name": "prev_app_version",
          "type": "string"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-820669733",
      "method": "messages.reportSpam",
      "params": [
        {
          "name": "peer",
          "type": "InputPeer"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-993483427",
      "method": "messages.getMessagesViews",
      "params": [
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "id",
          "type": "Vector<int>"
        },
        {
          "name": "increment",
          "type": "Bool"
        }
      ],
      "type": "Vector<int>"
    },
    {
      "id": "51854712",
      "method": "updates.getChannelDifference",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "force",
          "type": "flags.0?true"
        },
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "filter",
          "type": "ChannelMessagesFilter"
        },
        {
          "name": "pts",
          "type": "int"
        },
        {
          "name": "limit",
          "type": "int"
        }
      ],
      "type": "updates.ChannelDifference"
    },
    {
      "id": "-871347913",
      "method": "channels.readHistory",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "max_id",
          "type": "int"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-2067661490",
      "method": "channels.deleteMessages",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "id",
          "type": "Vector<int>"
        }
      ],
      "type": "messages.AffectedMessages"
    },
    {
      "id": "-787622117",
      "method": "channels.deleteUserHistory",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "user_id",
          "type": "InputUser"
        }
      ],
      "type": "messages.AffectedHistory"
    },
    {
      "id": "-32999408",
      "method": "channels.reportSpam",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "user_id",
          "type": "InputUser"
        },
        {
          "name": "id",
          "type": "Vector<int>"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-1814580409",
      "method": "channels.getMessages",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "id",
          "type": "Vector<int>"
        }
      ],
      "type": "messages.Messages"
    },
    {
      "id": "618237842",
      "method": "channels.getParticipants",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "filter",
          "type": "ChannelParticipantsFilter"
        },
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "limit",
          "type": "int"
        }
      ],
      "type": "channels.ChannelParticipants"
    },
    {
      "id": "1416484774",
      "method": "channels.getParticipant",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "user_id",
          "type": "InputUser"
        }
      ],
      "type": "channels.ChannelParticipant"
    },
    {
      "id": "176122811",
      "method": "channels.getChannels",
      "params": [
        {
          "name": "id",
          "type": "Vector<InputChannel>"
        }
      ],
      "type": "messages.Chats"
    },
    {
      "id": "141781513",
      "method": "channels.getFullChannel",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        }
      ],
      "type": "messages.ChatFull"
    },
    {
      "id": "-192332417",
      "method": "channels.createChannel",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "broadcast",
          "type": "flags.0?true"
        },
        {
          "name": "megagroup",
          "type": "flags.1?true"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "about",
          "type": "string"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "333610782",
      "method": "channels.editAbout",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "about",
          "type": "string"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "548962836",
      "method": "channels.editAdmin",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "user_id",
          "type": "InputUser"
        },
        {
          "name": "admin_rights",
          "type": "ChannelAdminRights"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "1450044624",
      "method": "channels.editTitle",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "title",
          "type": "string"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-248621111",
      "method": "channels.editPhoto",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "photo",
          "type": "InputChatPhoto"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "283557164",
      "method": "channels.checkUsername",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "username",
          "type": "string"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "890549214",
      "method": "channels.updateUsername",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "username",
          "type": "string"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "615851205",
      "method": "channels.joinChannel",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-130635115",
      "method": "channels.leaveChannel",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "429865580",
      "method": "channels.inviteToChannel",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "users",
          "type": "Vector<InputUser>"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-950663035",
      "method": "channels.exportInvite",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        }
      ],
      "type": "ExportedChatInvite"
    },
    {
      "id": "-1072619549",
      "method": "channels.deleteChannel",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-326379039",
      "method": "messages.toggleChatAdmins",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "enabled",
          "type": "Bool"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-1444503762",
      "method": "messages.editChatAdmin",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        },
        {
          "name": "user_id",
          "type": "InputUser"
        },
        {
          "name": "is_admin",
          "type": "Bool"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "363051235",
      "method": "messages.migrateChat",
      "params": [
        {
          "name": "chat_id",
          "type": "int"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-1640190800",
      "method": "messages.searchGlobal",
      "params": [
        {
          "name": "q",
          "type": "string"
        },
        {
          "name": "offset_date",
          "type": "int"
        },
        {
          "name": "offset_peer",
          "type": "InputPeer"
        },
        {
          "name": "offset_id",
          "type": "int"
        },
        {
          "name": "limit",
          "type": "int"
        }
      ],
      "type": "messages.Messages"
    },
    {
      "id": "-1374118561",
      "method": "account.reportPeer",
      "params": [
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "reason",
          "type": "ReportReason"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "2016638777",
      "method": "messages.reorderStickerSets",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "masks",
          "type": "flags.0?true"
        },
        {
          "name": "order",
          "type": "Vector<long>"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "889286899",
      "method": "help.getTermsOfService",
      "params": [],
      "type": "help.TermsOfService"
    },
    {
      "id": "864953444",
      "method": "messages.getDocumentByHash",
      "params": [
        {
          "name": "sha256",
          "type": "bytes"
        },
        {
          "name": "size",
          "type": "int"
        },
        {
          "name": "mime_type",
          "type": "string"
        }
      ],
      "type": "Document"
    },
    {
      "id": "-1080395925",
      "method": "messages.searchGifs",
      "params": [
        {
          "name": "q",
          "type": "string"
        },
        {
          "name": "offset",
          "type": "int"
        }
      ],
      "type": "messages.FoundGifs"
    },
    {
      "id": "-2084618926",
      "method": "messages.getSavedGifs",
      "params": [
        {
          "name": "hash",
          "type": "int"
        }
      ],
      "type": "messages.SavedGifs"
    },
    {
      "id": "846868683",
      "method": "messages.saveGif",
      "params": [
        {
          "name": "id",
          "type": "InputDocument"
        },
        {
          "name": "unsave",
          "type": "Bool"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "1364105629",
      "method": "messages.getInlineBotResults",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "bot",
          "type": "InputUser"
        },
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "geo_point",
          "type": "flags.0?InputGeoPoint"
        },
        {
          "name": "query",
          "type": "string"
        },
        {
          "name": "offset",
          "type": "string"
        }
      ],
      "type": "messages.BotResults"
    },
    {
      "id": "-346119674",
      "method": "messages.setInlineBotResults",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "gallery",
          "type": "flags.0?true"
        },
        {
          "name": "private",
          "type": "flags.1?true"
        },
        {
          "name": "query_id",
          "type": "long"
        },
        {
          "name": "results",
          "type": "Vector<InputBotInlineResult>"
        },
        {
          "name": "cache_time",
          "type": "int"
        },
        {
          "name": "next_offset",
          "type": "flags.2?string"
        },
        {
          "name": "switch_pm",
          "type": "flags.3?InlineBotSwitchPM"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-1318189314",
      "method": "messages.sendInlineBotResult",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "silent",
          "type": "flags.5?true"
        },
        {
          "name": "background",
          "type": "flags.6?true"
        },
        {
          "name": "clear_draft",
          "type": "flags.7?true"
        },
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "reply_to_msg_id",
          "type": "flags.0?int"
        },
        {
          "name": "random_id",
          "type": "long"
        },
        {
          "name": "query_id",
          "type": "long"
        },
        {
          "name": "id",
          "type": "string"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "1231065863",
      "method": "channels.toggleInvites",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "enabled",
          "type": "Bool"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-934882771",
      "method": "channels.exportMessageLink",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "id",
          "type": "int"
        }
      ],
      "type": "ExportedMessageLink"
    },
    {
      "id": "527021574",
      "method": "channels.toggleSignatures",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "enabled",
          "type": "Bool"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-1460572005",
      "method": "messages.hideReportSpam",
      "params": [
        {
          "name": "peer",
          "type": "InputPeer"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "913498268",
      "method": "messages.getPeerSettings",
      "params": [
        {
          "name": "peer",
          "type": "InputPeer"
        }
      ],
      "type": "PeerSettings"
    },
    {
      "id": "-1490162350",
      "method": "channels.updatePinnedMessage",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "silent",
          "type": "flags.0?true"
        },
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "id",
          "type": "int"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "1056025023",
      "method": "auth.resendCode",
      "params": [
        {
          "name": "phone_number",
          "type": "string"
        },
        {
          "name": "phone_code_hash",
          "type": "string"
        }
      ],
      "type": "auth.SentCode"
    },
    {
      "id": "520357240",
      "method": "auth.cancelCode",
      "params": [
        {
          "name": "phone_number",
          "type": "string"
        },
        {
          "name": "phone_code_hash",
          "type": "string"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-39416522",
      "method": "messages.getMessageEditData",
      "params": [
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "id",
          "type": "int"
        }
      ],
      "type": "messages.MessageEditData"
    },
    {
      "id": "-829299510",
      "method": "messages.editMessage",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "no_webpage",
          "type": "flags.1?true"
        },
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "message",
          "type": "flags.11?string"
        },
        {
          "name": "reply_markup",
          "type": "flags.2?ReplyMarkup"
        },
        {
          "name": "entities",
          "type": "flags.3?Vector<MessageEntity>"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "319564933",
      "method": "messages.editInlineBotMessage",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "no_webpage",
          "type": "flags.1?true"
        },
        {
          "name": "id",
          "type": "InputBotInlineMessageID"
        },
        {
          "name": "message",
          "type": "flags.11?string"
        },
        {
          "name": "reply_markup",
          "type": "flags.2?ReplyMarkup"
        },
        {
          "name": "entities",
          "type": "flags.3?Vector<MessageEntity>"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-2130010132",
      "method": "messages.getBotCallbackAnswer",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "game",
          "type": "flags.1?true"
        },
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "msg_id",
          "type": "int"
        },
        {
          "name": "data",
          "type": "flags.0?bytes"
        }
      ],
      "type": "messages.BotCallbackAnswer"
    },
    {
      "id": "-712043766",
      "method": "messages.setBotCallbackAnswer",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "alert",
          "type": "flags.1?true"
        },
        {
          "name": "query_id",
          "type": "long"
        },
        {
          "name": "message",
          "type": "flags.0?string"
        },
        {
          "name": "url",
          "type": "flags.2?string"
        },
        {
          "name": "cache_time",
          "type": "int"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-728224331",
      "method": "contacts.getTopPeers",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "correspondents",
          "type": "flags.0?true"
        },
        {
          "name": "bots_pm",
          "type": "flags.1?true"
        },
        {
          "name": "bots_inline",
          "type": "flags.2?true"
        },
        {
          "name": "phone_calls",
          "type": "flags.3?true"
        },
        {
          "name": "groups",
          "type": "flags.10?true"
        },
        {
          "name": "channels",
          "type": "flags.15?true"
        },
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "limit",
          "type": "int"
        },
        {
          "name": "hash",
          "type": "int"
        }
      ],
      "type": "contacts.TopPeers"
    },
    {
      "id": "451113900",
      "method": "contacts.resetTopPeerRating",
      "params": [
        {
          "name": "category",
          "type": "TopPeerCategory"
        },
        {
          "name": "peer",
          "type": "InputPeer"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "764901049",
      "method": "messages.getPeerDialogs",
      "params": [
        {
          "name": "peers",
          "type": "Vector<InputPeer>"
        }
      ],
      "type": "messages.PeerDialogs"
    },
    {
      "id": "-1137057461",
      "method": "messages.saveDraft",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "no_webpage",
          "type": "flags.1?true"
        },
        {
          "name": "reply_to_msg_id",
          "type": "flags.0?int"
        },
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "message",
          "type": "string"
        },
        {
          "name": "entities",
          "type": "flags.3?Vector<MessageEntity>"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "1782549861",
      "method": "messages.getAllDrafts",
      "params": [],
      "type": "Updates"
    },
    {
      "id": "353818557",
      "method": "account.sendConfirmPhoneCode",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "allow_flashcall",
          "type": "flags.0?true"
        },
        {
          "name": "hash",
          "type": "string"
        },
        {
          "name": "current_number",
          "type": "flags.0?Bool"
        }
      ],
      "type": "auth.SentCode"
    },
    {
      "id": "1596029123",
      "method": "account.confirmPhone",
      "params": [
        {
          "name": "phone_code_hash",
          "type": "string"
        },
        {
          "name": "phone_code",
          "type": "string"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "766298703",
      "method": "messages.getFeaturedStickers",
      "params": [
        {
          "name": "hash",
          "type": "int"
        }
      ],
      "type": "messages.FeaturedStickers"
    },
    {
      "id": "1527873830",
      "method": "messages.readFeaturedStickers",
      "params": [
        {
          "name": "id",
          "type": "Vector<long>"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "1587647177",
      "method": "messages.getRecentStickers",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "attached",
          "type": "flags.0?true"
        },
        {
          "name": "hash",
          "type": "int"
        }
      ],
      "type": "messages.RecentStickers"
    },
    {
      "id": "958863608",
      "method": "messages.saveRecentSticker",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "attached",
          "type": "flags.0?true"
        },
        {
          "name": "id",
          "type": "InputDocument"
        },
        {
          "name": "unsave",
          "type": "Bool"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-1986437075",
      "method": "messages.clearRecentStickers",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "attached",
          "type": "flags.0?true"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "1475442322",
      "method": "messages.getArchivedStickers",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "masks",
          "type": "flags.0?true"
        },
        {
          "name": "offset_id",
          "type": "long"
        },
        {
          "name": "limit",
          "type": "int"
        }
      ],
      "type": "messages.ArchivedStickers"
    },
    {
      "id": "-1920105769",
      "method": "channels.getAdminedPublicChannels",
      "params": [],
      "type": "messages.Chats"
    },
    {
      "id": "-1907842680",
      "method": "auth.dropTempAuthKeys",
      "params": [
        {
          "name": "except_auth_keys",
          "type": "Vector<long>"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-1896289088",
      "method": "messages.setGameScore",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "edit_message",
          "type": "flags.0?true"
        },
        {
          "name": "force",
          "type": "flags.1?true"
        },
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "user_id",
          "type": "InputUser"
        },
        {
          "name": "score",
          "type": "int"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "363700068",
      "method": "messages.setInlineGameScore",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "edit_message",
          "type": "flags.0?true"
        },
        {
          "name": "force",
          "type": "flags.1?true"
        },
        {
          "name": "id",
          "type": "InputBotInlineMessageID"
        },
        {
          "name": "user_id",
          "type": "InputUser"
        },
        {
          "name": "score",
          "type": "int"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "1706608543",
      "method": "messages.getMaskStickers",
      "params": [
        {
          "name": "hash",
          "type": "int"
        }
      ],
      "type": "messages.AllStickers"
    },
    {
      "id": "-866424884",
      "method": "messages.getAttachedStickers",
      "params": [
        {
          "name": "media",
          "type": "InputStickeredMedia"
        }
      ],
      "type": "Vector<StickerSetCovered>"
    },
    {
      "id": "-400399203",
      "method": "messages.getGameHighScores",
      "params": [
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "id",
          "type": "int"
        },
        {
          "name": "user_id",
          "type": "InputUser"
        }
      ],
      "type": "messages.HighScores"
    },
    {
      "id": "258170395",
      "method": "messages.getInlineGameHighScores",
      "params": [
        {
          "name": "id",
          "type": "InputBotInlineMessageID"
        },
        {
          "name": "user_id",
          "type": "InputUser"
        }
      ],
      "type": "messages.HighScores"
    },
    {
      "id": "218777796",
      "method": "messages.getCommonChats",
      "params": [
        {
          "name": "user_id",
          "type": "InputUser"
        },
        {
          "name": "max_id",
          "type": "int"
        },
        {
          "name": "limit",
          "type": "int"
        }
      ],
      "type": "messages.Chats"
    },
    {
      "id": "-341307408",
      "method": "messages.getAllChats",
      "params": [
        {
          "name": "except_ids",
          "type": "Vector<int>"
        }
      ],
      "type": "messages.Chats"
    },
    {
      "id": "-333262899",
      "method": "help.setBotUpdatesStatus",
      "params": [
        {
          "name": "pending_updates_count",
          "type": "int"
        },
        {
          "name": "message",
          "type": "string"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "852135825",
      "method": "messages.getWebPage",
      "params": [
        {
          "name": "url",
          "type": "string"
        },
        {
          "name": "hash",
          "type": "int"
        }
      ],
      "type": "WebPage"
    },
    {
      "id": "847887978",
      "method": "messages.toggleDialogPin",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "pinned",
          "type": "flags.0?true"
        },
        {
          "name": "peer",
          "type": "InputPeer"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-1784678844",
      "method": "messages.reorderPinnedDialogs",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "force",
          "type": "flags.0?true"
        },
        {
          "name": "order",
          "type": "Vector<InputPeer>"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-497756594",
      "method": "messages.getPinnedDialogs",
      "params": [],
      "type": "messages.PeerDialogs"
    },
    {
      "id": "1536537556",
      "method": "phone.requestCall",
      "params": [
        {
          "name": "user_id",
          "type": "InputUser"
        },
        {
          "name": "random_id",
          "type": "int"
        },
        {
          "name": "g_a_hash",
          "type": "bytes"
        },
        {
          "name": "protocol",
          "type": "PhoneCallProtocol"
        }
      ],
      "type": "phone.PhoneCall"
    },
    {
      "id": "1003664544",
      "method": "phone.acceptCall",
      "params": [
        {
          "name": "peer",
          "type": "InputPhoneCall"
        },
        {
          "name": "g_b",
          "type": "bytes"
        },
        {
          "name": "protocol",
          "type": "PhoneCallProtocol"
        }
      ],
      "type": "phone.PhoneCall"
    },
    {
      "id": "2027164582",
      "method": "phone.discardCall",
      "params": [
        {
          "name": "peer",
          "type": "InputPhoneCall"
        },
        {
          "name": "duration",
          "type": "int"
        },
        {
          "name": "reason",
          "type": "PhoneCallDiscardReason"
        },
        {
          "name": "connection_id",
          "type": "long"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "399855457",
      "method": "phone.receivedCall",
      "params": [
        {
          "name": "peer",
          "type": "InputPhoneCall"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "1259113487",
      "method": "messages.reportEncryptedSpam",
      "params": [
        {
          "name": "peer",
          "type": "InputEncryptedChat"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-1712285883",
      "method": "payments.getPaymentForm",
      "params": [
        {
          "name": "msg_id",
          "type": "int"
        }
      ],
      "type": "payments.PaymentForm"
    },
    {
      "id": "730364339",
      "method": "payments.sendPaymentForm",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "msg_id",
          "type": "int"
        },
        {
          "name": "requested_info_id",
          "type": "flags.0?string"
        },
        {
          "name": "shipping_option_id",
          "type": "flags.1?string"
        },
        {
          "name": "credentials",
          "type": "InputPaymentCredentials"
        }
      ],
      "type": "payments.PaymentResult"
    },
    {
      "id": "1250046590",
      "method": "account.getTmpPassword",
      "params": [
        {
          "name": "password_hash",
          "type": "bytes"
        },
        {
          "name": "period",
          "type": "int"
        }
      ],
      "type": "account.TmpPassword"
    },
    {
      "id": "-436833542",
      "method": "messages.setBotShippingResults",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "query_id",
          "type": "long"
        },
        {
          "name": "error",
          "type": "flags.0?string"
        },
        {
          "name": "shipping_options",
          "type": "flags.1?Vector<ShippingOption>"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "163765653",
      "method": "messages.setBotPrecheckoutResults",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "success",
          "type": "flags.1?true"
        },
        {
          "name": "query_id",
          "type": "long"
        },
        {
          "name": "error",
          "type": "flags.0?string"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "619086221",
      "method": "upload.getWebFile",
      "params": [
        {
          "name": "location",
          "type": "InputWebFileLocation"
        },
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "limit",
          "type": "int"
        }
      ],
      "type": "upload.WebFile"
    },
    {
      "id": "-1440257555",
      "method": "bots.sendCustomRequest",
      "params": [
        {
          "name": "custom_method",
          "type": "string"
        },
        {
          "name": "params",
          "type": "DataJSON"
        }
      ],
      "type": "DataJSON"
    },
    {
      "id": "-434028723",
      "method": "bots.answerWebhookJSONQuery",
      "params": [
        {
          "name": "query_id",
          "type": "long"
        },
        {
          "name": "data",
          "type": "DataJSON"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-1601001088",
      "method": "payments.getPaymentReceipt",
      "params": [
        {
          "name": "msg_id",
          "type": "int"
        }
      ],
      "type": "payments.PaymentReceipt"
    },
    {
      "id": "1997180532",
      "method": "payments.validateRequestedInfo",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "save",
          "type": "flags.0?true"
        },
        {
          "name": "msg_id",
          "type": "int"
        },
        {
          "name": "info",
          "type": "PaymentRequestedInfo"
        }
      ],
      "type": "payments.ValidatedRequestedInfo"
    },
    {
      "id": "578650699",
      "method": "payments.getSavedInfo",
      "params": [],
      "type": "payments.SavedInfo"
    },
    {
      "id": "-667062079",
      "method": "payments.clearSavedInfo",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "credentials",
          "type": "flags.0?true"
        },
        {
          "name": "info",
          "type": "flags.1?true"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "1430593449",
      "method": "phone.getCallConfig",
      "params": [],
      "type": "DataJSON"
    },
    {
      "id": "788404002",
      "method": "phone.confirmCall",
      "params": [
        {
          "name": "peer",
          "type": "InputPhoneCall"
        },
        {
          "name": "g_a",
          "type": "bytes"
        },
        {
          "name": "key_fingerprint",
          "type": "long"
        },
        {
          "name": "protocol",
          "type": "PhoneCallProtocol"
        }
      ],
      "type": "phone.PhoneCall"
    },
    {
      "id": "475228724",
      "method": "phone.setCallRating",
      "params": [
        {
          "name": "peer",
          "type": "InputPhoneCall"
        },
        {
          "name": "rating",
          "type": "int"
        },
        {
          "name": "comment",
          "type": "string"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "662363518",
      "method": "phone.saveCallDebug",
      "params": [
        {
          "name": "peer",
          "type": "InputPhoneCall"
        },
        {
          "name": "debug",
          "type": "DataJSON"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "536919235",
      "method": "upload.getCdnFile",
      "params": [
        {
          "name": "file_token",
          "type": "bytes"
        },
        {
          "name": "offset",
          "type": "int"
        },
        {
          "name": "limit",
          "type": "int"
        }
      ],
      "type": "upload.CdnFile"
    },
    {
      "id": "452533257",
      "method": "upload.reuploadCdnFile",
      "params": [
        {
          "name": "file_token",
          "type": "bytes"
        },
        {
          "name": "request_token",
          "type": "bytes"
        }
      ],
      "type": "Vector<CdnFileHash>"
    },
    {
      "id": "1375900482",
      "method": "help.getCdnConfig",
      "params": [],
      "type": "CdnConfig"
    },
    {
      "id": "1369162417",
      "method": "messages.uploadMedia",
      "params": [
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "media",
          "type": "InputMedia"
        }
      ],
      "type": "MessageMedia"
    },
    {
      "id": "-1680314774",
      "method": "stickers.createStickerSet",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "masks",
          "type": "flags.0?true"
        },
        {
          "name": "user_id",
          "type": "InputUser"
        },
        {
          "name": "title",
          "type": "string"
        },
        {
          "name": "short_name",
          "type": "string"
        },
        {
          "name": "stickers",
          "type": "Vector<InputStickerSetItem>"
        }
      ],
      "type": "messages.StickerSet"
    },
    {
      "id": "-1699363442",
      "method": "langpack.getLangPack",
      "params": [
        {
          "name": "lang_code",
          "type": "string"
        }
      ],
      "type": "LangPackDifference"
    },
    {
      "id": "773776152",
      "method": "langpack.getStrings",
      "params": [
        {
          "name": "lang_code",
          "type": "string"
        },
        {
          "name": "keys",
          "type": "Vector<string>"
        }
      ],
      "type": "Vector<LangPackString>"
    },
    {
      "id": "187583869",
      "method": "langpack.getDifference",
      "params": [
        {
          "name": "from_version",
          "type": "int"
        }
      ],
      "type": "LangPackDifference"
    },
    {
      "id": "-2146445955",
      "method": "langpack.getLanguages",
      "params": [],
      "type": "Vector<LangPackLanguage>"
    },
    {
      "id": "-1076292147",
      "method": "channels.editBanned",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "user_id",
          "type": "InputUser"
        },
        {
          "name": "banned_rights",
          "type": "ChannelBannedRights"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "870184064",
      "method": "channels.getAdminLog",
      "params": [
        {
          "name": "flags",
          "type": "#"
        },
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "q",
          "type": "string"
        },
        {
          "name": "events_filter",
          "type": "flags.0?ChannelAdminLogEventsFilter"
        },
        {
          "name": "admins",
          "type": "flags.1?Vector<InputUser>"
        },
        {
          "name": "max_id",
          "type": "long"
        },
        {
          "name": "min_id",
          "type": "long"
        },
        {
          "name": "limit",
          "type": "int"
        }
      ],
      "type": "channels.AdminLogResults"
    },
    {
      "id": "-143257775",
      "method": "stickers.removeStickerFromSet",
      "params": [
        {
          "name": "sticker",
          "type": "InputDocument"
        }
      ],
      "type": "messages.StickerSet"
    },
    {
      "id": "-4795190",
      "method": "stickers.changeStickerPosition",
      "params": [
        {
          "name": "sticker",
          "type": "InputDocument"
        },
        {
          "name": "position",
          "type": "int"
        }
      ],
      "type": "messages.StickerSet"
    },
    {
      "id": "-2041315650",
      "method": "stickers.addStickerToSet",
      "params": [
        {
          "name": "stickerset",
          "type": "InputStickerSet"
        },
        {
          "name": "sticker",
          "type": "InputStickerSetItem"
        }
      ],
      "type": "messages.StickerSet"
    },
    {
      "id": "-914493408",
      "method": "messages.sendScreenshotNotification",
      "params": [
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "reply_to_msg_id",
          "type": "int"
        },
        {
          "name": "random_id",
          "type": "long"
        }
      ],
      "type": "Updates"
    },
    {
      "id": "-149567365",
      "method": "upload.getCdnFileHashes",
      "params": [
        {
          "name": "file_token",
          "type": "bytes"
        },
        {
          "name": "offset",
          "type": "int"
        }
      ],
      "type": "Vector<CdnFileHash>"
    },
    {
      "id": "1180140658",
      "method": "messages.getUnreadMentions",
      "params": [
        {
          "name": "peer",
          "type": "InputPeer"
        },
        {
          "name": "offset_id",
          "type": "int"
        },
        {
          "name": "add_offset",
          "type": "int"
        },
        {
          "name": "limit",
          "type": "int"
        },
        {
          "name": "max_id",
          "type": "int"
        },
        {
          "name": "min_id",
          "type": "int"
        }
      ],
      "type": "messages.Messages"
    },
    {
      "id": "-1174420133",
      "method": "messages.faveSticker",
      "params": [
        {
          "name": "id",
          "type": "InputDocument"
        },
        {
          "name": "unfave",
          "type": "Bool"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-359881479",
      "method": "channels.setStickers",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "stickerset",
          "type": "InputStickerSet"
        }
      ],
      "type": "Bool"
    },
    {
      "id": "-2020263951",
      "method": "contacts.resetSaved",
      "params": [],
      "type": "Bool"
    },
    {
      "id": "567151374",
      "method": "messages.getFavedStickers",
      "params": [
        {
          "name": "hash",
          "type": "int"
        }
      ],
      "type": "messages.FavedStickers"
    },
    {
      "id": "-357180360",
      "method": "channels.readMessageContents",
      "params": [
        {
          "name": "channel",
          "type": "InputChannel"
        },
        {
          "name": "id",
          "type": "Vector<int>"
        }
      ],
      "type": "Bool"
    }
  ]
}

Config.Schema.API.layer = 71

export default Config