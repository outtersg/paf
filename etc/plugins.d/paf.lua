if confighelp then
  return
end

local N = 'paf'

local fun = require 'fun'
local rspamd_logger = require 'rspamd_logger'
local regexp = require 'rspamd_regexp'
local util = require 'rspamd_util'

--------------------------------------------------------------------------------
-- Utilitaires.

-- Argh, Lua 5.1 n'inclut ni bit32 ni opérateurs bit à bit!
local function bit32_rshift(n, nbits)
	return math.floor(n / 2 ^ nbits)
end
local function bit32_band(x, y) -- /!\ Ne fonctionne que pour un y ayant tous ses bits à droite.
	return x % (y + 1)
end

-- Transforme une chaîne \uXXXX en le caractère UTF-8 correspondant.
local function uechapp(u)
	local n, pre, paq, c
	local ch
	u = u:sub(3)
	n = tonumber('0x'..u)
	-- http://lua-users.org/wiki/LuaUnicode "UTF8 decoding function"
	pre = -- Nombre de bits de préfixe.
		n >= 0x4000000 and 6 or
		n >= 0x200000 and 5 or
		n >= 0x10000 and 4 or
		n >= 0x800 and 3 or
		n >= 0x80 and 2 or
		0
	paq = pre > 0 and pre - 1 or 0 -- Nombre de paquets de 6 bits hors l'octet portant le préfixe.
	c = (0x100 - 2 ^ (8 - pre)) + bit32_rshift(n, 6 * paq)
	ch = string.char(c)
	while paq > 0 do
		paq = paq - 1
		ch = ch..string.char(0x80 + bit32_band(bit32_rshift(n, 6 * paq), 0x3F))
	end
	return ch
end

--------------------------------------------------------------------------------
-- Objets.

local PafEnsemble = {}
local PafEnsemble__mt = { __index = PafEnsemble }

function PafEnsemble.new(init)
	local this = init
	if not this then
		this = {}
	end
	setmetatable(this, PafEnsemble__mt)
	return this
end

--------------------------------------------------------------------------------
-- Traitement.

local function calculerEnTetes(tache)
	if not tache.enTetes then
		local enTetes = ''
		local parties = tache.t:get_parts()
		tache.t:headers_foreach(function(nom, valeur)
			enTetes = enTetes..nom..': '..valeur:gsub('\n', ' ')..'\n'
		end)
		-- Zut, si on n'a réussi à récupérer les en-têtes propres, on n'a que la version malpropre (avec des <LF><espace> pour les en-têtes trop longs, et des en-têtes UTF-8 encore encodés). Mais c'est mieux que rien.
		if enTetes == '' then
			rspamd_logger.infox(tache.t, 'unable to find clean headers of message, reverting to raw headers')
			enTetes = tache.t:get_raw_headers()
		end
		tache.enTetes = enTetes
	end
	return tache.enTetes
end

local purgesHtml =
{
	{ '[\r\n\002\003\011]', ' ' },
	{ '<(/*)[dD][iI][vV]>', '\002%1div\003' },
	{ '<(/*)[dD][iI][vV] [^>]*>', '\002%1div\003' },
	{ '<[bB][rR]/*>', '\002br/\003' },
	{ '<(/*)[aA]>', '\002%1a\003' },
	{ '<[aA] [^>]*[hH][rR][eE][fF]="*([^ "]*)"*[^>]*>', '\002a href="%1"\003' },
	-- Les img, aussi, sans doute?
	{ '<[^>]*>', '' },
	{ '\002', '<' },
	{ '\003', '>' },
	{ '<br/>', '\n' },
	{ '<div>', '\n' },
	{ '</div>', '' },
	{ '&nbsp;', ' ' }, -- Espace insécable. Le transformer en espace pour simplifier l'analyse?
}
local function purgeHtml(c)
	-- À FAIRE: toutes les entités &…;
	for _,purge in ipairs(purgesHtml) do
		c = c:gsub(purge[1], purge[2])
	end
	return c
end

local function _boutsTexte(t, contenus)
	-- Selon que l'on arrive de la task ou d'un multipart, les sous-éléments ne se récupèrent pas de la même manière.
	local bouts = (t.get_parts and t:get_parts()) or t:get_children()
	if bouts then
		local nAvant = 0
		local v
		for v in pairs(contenus) do nAvant = nAvant + 1 end
		for _,bout in ipairs(bouts) do
			if bout:is_multipart() then
				local fistons = bout:get_children() or {}
				for _,fiston in ipairs(fistons) do
					_boutsTexte(fiston, contenus)
				end
			elseif bout:is_text() then
				table.insert(contenus, bout)
			else
			end
		end
		local nApres = 0
		for v in pairs(contenus) do nApres = nApres + 1 end
		if nApres <= nAvant then
		-- Des gugusses qui envoient du spam non-MIME, avec des Content-Type: text/plain; (point-virgule sans rien derrière) pour outrepasser le filtrage.
		for _,bout in ipairs(bouts) do
			local type = bout:get_header('Content-Type')
			if not type or type:sub(1, 4) == 'text' then
				table.insert(contenus, bout)
				end
			end
		end
	end
end

local function boutsTexte(colis)
	local contenus = {}
	_boutsTexte(colis.t, contenus)
	return contenus
end

-- boutsTexte du temps où il n'existait pas le is_multipart.
local function boutsTexte0(tache)
	local contenus = {}
	local trouve = false
	local bouts = colis.t:get_text_parts()
	if bouts then
		for _,bout in ipairs(bouts) do
			table.insert(contenus, bout)
			trouve = true
		end
	end
	if not trouve then
		-- Des gugusses qui envoient du spam non-MIME, avec des Content-Type: text/plain; (point-virgule sans rien derrière) pour outrepasser le filtrage.
		bouts = colis.t:get_parts()
		for _,bout in ipairs(bouts) do
			local type = bout:get_header('Content-Type')
			if not type or type:sub(1, 4) == 'text' then
				table.insert(contenus, bout)
			end
		end
	end
	return contenus
end

local function textesBruts(colis)
	local textesBruts = {}
	for _,bout in ipairs(boutsTexte(colis)) do
		table.insert(textesBruts, bout:get_content())
	end
	return textesBruts
end

local function textesPurges(colis)
	if not colis.texte then
		colis.texte = {}
		local contenu
		for _,bout in ipairs(boutsTexte(colis)) do
			if type(bout.is_html) == 'function' and bout:is_html() then
				-- À FAIRE: vérifier que la mise-en-page des retours à la ligne est préservée (en HTML: <br/> donne un retour à la ligne, <p> donne deux retours à la ligne).
				contenu = purgeHtml(tostring(bout:get_content('raw_utf')))
			else
				contenu = bout:get_content()
			end
			table.insert(colis.texte, contenu)
		end
	end
	return colis.texte
end

local function affDiag(fichier, libelle, contenu)
	local i, bloc, prefixe
	prefixe = ''
	if libelle then
		prefixe = libelle..'.'
	end
	if type(contenu) == 'string' or type(contenu) == 'number' then
		fichier:write("\n=== "..libelle.." ===\n\n")
		fichier:write(contenu)
		fichier:write("\n")
	elseif type(contenu.get_content) == 'function' then
		affDiag(fichier, prefixe..'getContent()', contenu:get_content())
	elseif type(contenu.str) == 'function' then
		affDiag(fichier, prefixe..'str()', contenu:str())
	elseif type(contenu) == 'table' then
		for i,bloc in pairs(contenu) do
			affDiag(fichier, prefixe..i, bloc)
		end
	end
end

local function diag(colis)
	-- Idéalement il faudrait que l'on puisse détecter le niveau de trace pour décider si on affiche ou non.
	local err, infos = util.stat('/tmp/zebu')
	if err then
		return
	end
	local fichier = io.open("/tmp/zebu", "a")
	fichier:write("================================\n")
	affDiag(fichier, nil, colis)
	fichier:close()
end

local function calcule(regle, colis)
	local e = load("return "..regle.e, nil, 't', colis.symboles)
	local toutbon
	toutbon, e = pcall(e)
	if toutbon then
		return (type(e) == 'number' and e) or (e and 1) or 0
	end
	return 0
end

local function chope(regle, tache)
	local contenus

	-- Extraction des contenus à analyser.
	
	if regle.type == 'r' then
		contenus = { tache.t:get_content() }
	elseif regle.type == 'h' then
		contenus = { calculerEnTetes(tache) }
	elseif regle.type == 't' then -- Texte
		contenus = textesBruts(tache)
	elseif regle.type == 'T' then -- Texte avec <a> préservés.
		contenus = textesPurges(tache)
	-- À FAIRE: les autres cas.
	else
		rspamd_logger.errx(tache.t, 'unknown type [%s]', regle.type)
	end

	-- Analyse.

	if contenus then
		if regle.adesfois then
			local fois = 0
			local cettefois
			for _, contenu in ipairs(contenus) do
				cettefois = regle.e:matchn(contenu, -1)
				if cettefois > fois then
					fois = cettefois
				end
			end
			return fois
		else
			for _, contenu in ipairs(contenus) do
				if regle.e:match(contenu) then
					return 1
				end
			end
		end
	end
end

local function analyse(regle, colis)
	if regle.type == '=' then
		return calcule(regle, colis)
	else
		return chope(regle, colis)
	end
end

function PafEnsemble.paf(this, tache)
	if this.dateRegles then
		local err, infos = util.stat(this.chemin)
		if err then
			rspamd_logger.errx(rspamd_config, 'Unable to stat %s (%s). Auto-reload will be deactivated.', this.chemin, err)
			this.dateRegles = nil
		elseif infos.mtime > this.dateRegles then
			rspamd_logger.errx(rspamd_config, 'Rules changed (%s). Reloading.', this.chemin)
			this:charger()
			this.dateRegles = infos.mtime
		end
	end

	local points = 0.0
	local touchees = {}
	local colis = { t = tache, symboles = {} }
	for _, regle in ipairs(this.regles) do
		local nfois = analyse(regle, colis)
		if nfois and nfois == 0.0 then
			nfois = nil
		end
		if nfois then
			if regle.points then
			points = points + nfois * regle.points
			end
			local exp = (type(regle.e) == 'string' and regle.e) or regle.e:get_pattern()
			if exp:len() > 24 then
				exp = exp:sub(1, 23)..'…'
			end
			local chainenfois = nfois ~= 1 and nfois..'*' or ''
			table.insert(touchees, chainenfois..'['..regle.ligne..'] '..exp)
		end
		if regle.symboles then
			local symbole, rs, ps
			for symbole, rs in pairs(regle.symboles) do
				ps = nfois and (rs.fois and rs.points * nfois or rs.points) or 0
				if colis.symboles[symbole] == nil or math.abs(ps) > math.abs(colis.symboles[symbole]) then
					colis.symboles[symbole] = ps
				end
			end
		end
	end
	diag(colis)
	if #touchees > 0 then
		tache:insert_result(this.nom, points, table.concat(touchees, ', '))
	end
end

function PafEnsemble.gen_appel(this)
	return function(tache)
		return this:paf(tache)
	end
end

--------------------------------------------------------------------------------
-- Chargement.

function PafEnsemble.charger(this)
	local regles = {}
	local f, err = io.open(this.chemin, 'r')
	if err then
		rspamd_logger.errx(rspamd_config, 'Unable to read paf rules file '%s': %s', this.chemin, err)
		return
	end
	
	-- À FAIRE: pointssymbole, ex. SYMBOLE*70 ou 70:SYMBOLE*, pour signifier de combien on incrémente le symbole. Permet par exemple juste après d'annuler tous les points accumulés (ex.: h BON From: bon ; t 70:MAUVAIS* spam ; = = BON * -MAUVAIS # Si BON, on ajoute -MAUVAIS points, annulant l'effet de la règle ayant calculé MAUVAIS).
	-- À FAIRE: SYMBOLE! exporte un symbole global (au même titre que G_PAF)
	
	local accepteurRegle = regexp.create('/^([=a-zA-Z]+)([*]?)[ \t]+([-0-9_a-zA-Z=*,:;+]+)[ \t]+(.*)$/')
	local accepteurRes = regexp.create('/(^|[,:;+])(([-]?[0-9]+)|([a-zA-Z][a-zA-Z_0-9]*)(=([-]?[0-9]+))?)([*]?)/')
	
	local num = 0
	for l in f:lines() do
		num = num + 1
		l = l:gsub('^#.*', ''):gsub('[ \t]*[ \t]# .*', ''):gsub('^%s+', ''):gsub('%s+$', '')
		if l:len() then
			local res = accepteurRegle:search(l, true, true)
			if res ~= nil then
				res = res[1]
				local marqueurs = res[2]
				local mfois = res[3]
				local exp = res[5]
				res = res[4]
				local e
				if marqueurs == '=' then
					-- À FAIRE: précompiler
					-- À FAIRE: remplacer tout ce qui ressemble à une regex (/…/{sélecteur}) par le regexp.create correspondant (PCRE, plus puissant que les regex Lua). Utiliser les sélecteurs https://rspamd.com/doc/lua/rspamd_regexp.html. Une fois l'objet regex créé, on pourra par exemple le référencer (remplacer la regex dans la chaîne à load()er) sous un nom d'après séquence, qui sera publié dans l'env passé au load.
					-- À FAIRE: varier les balises à regex (ex.: @…@), pour permettre par exemple du http:// dedans sans avoir à déspécifier les /
					e = exp
				else
					exp = exp:gsub('\\u[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]', uechapp)
					e = regexp.create(exp)
				end
				if not e then
					rspamd_logger.errx(rspamd_config, 'Expression is not a regex: %s', exp)
				else
					local boutsRes = accepteurRes:search(res, true, true)
					if boutsRes then
						local boutRes
						-- search() nous renvoie tout fragment accepté, mais ne nous dit pas s'il ne reste pas des "trous" entre (des chaînes non prises en compte). Pour savoir si notre résultat n'est bien constitué que de fragments valides, on compare la taille.
						local tailleRes = 0
						for _,boutRes in pairs(boutsRes) do
							tailleRes = tailleRes + boutRes[1]:len()
						end
						if tailleRes == res:len() then
					local fois = mfois == '*'
							local r = { ligne = num, type = marqueurs, adesfois = fois, e = e }
							for _,boutRes in ipairs(boutsRes) do
								if boutRes[4] ~= '' then -- Nombre de points.
									r.points = 0 + boutRes[4]
									r.fois = fois or boutRes[8] == '*'
								else -- Symbole.
									if not r.symboles then
										r.symboles = {}
									end
									r.symboles[boutRes[5]] = { points = boutRes[7] == '' and 1 or 0 + boutRes[7], fois = fois or boutRes[8] == '*' }
								end
								if boutRes[8] == '*' then
									r.adesfois = true
								end
							end
							table.insert(regles, r)
						else
							rspamd_logger.errx(rspamd_config, 'Invalid rule result: %s', res)
						end
					else
						rspamd_logger.errx(rspamd_config, 'Invalid rule result: %s', res)
					end
				end
			end
		end
	end

	accepteurRegle:destroy()

	if #regles <= 0 then
		rspamd_logger.infox(rspamd_config, 'No rule in paf set \'%s\', skipping', this.nom)
	else
		rspamd_logger.infox(rspamd_config, 'Registered paf set \'%s\' with %s entries', this.nom, #regles)
	end
	this.regles = regles
end

local function ensemble_charger(nom, params)
	local e = PafEnsemble.new({ nom = nom, chemin = params['rules'] })
	if params.reload then
		local err, infos = util.stat(e.chemin)
		if err then
			rspamd_logger.errx(rspamd_config, 'Unable to stat %s (%s). Auto-reload will not be activated.', e.chemin, err)
		else
			e.dateRegles = infos.mtime
		end
	end

	-- Le symbole est inscrit.
	
	rspamd_config:register_symbol(
	{
		type = 'normal',
		name = nom,
		callback = e:gen_appel(),
	})

	-- Ainsi que le fait qu'il compte.

	rspamd_config:set_metric_symbol(
	{
		name = nom,
		score = params['score'],
		description = 'paf set',
		group = N,
	})

	rspamd_logger.errx(rspamd_config, 'paf: init with rules at %s', e.chemin, err)
	e:charger()
end

--------------------------------------------------------------------------------
-- Amorce.

-- À FAIRE: colorisation vim sur le .regles
-- À FAIRE: "définitions": choper une capture dans des expressions en début de fichier pour les réinjecter ensuite (ex.: PJ dont le nom est l'un des Subject:) (/!\ Attention: les expressions contenant une variable ne pourront donc pas être compilées avant la définition aura tourné en première passe)
-- À FAIRE: optimisation: faire des paquets de regex, en les séparant par des |; ainsi si on matche l'une de ces macro-regex, on sait qu'il faut ensuite rentrer dans le détail une par une pour avoir le détail, mais au moins on passe rapidement sur les "gentils" méls qui n'ont rien à se reprocher.

local opts = rspamd_config:get_all_opt(N)
if opts and type(opts) == 'table' then
	for nom, m in pairs(opts) do
		if type(m) == 'table' and m['rules'] then
			if not m['score'] then
				rspamd_logger.errx(rspamd_config, 'paf set \'%s\' should have a score', nom)
			else
				ensemble_charger(nom, m)
			end
		end
	end
end
