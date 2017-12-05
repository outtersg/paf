if confighelp then
  return
end

local N = 'paf'

local fun = require 'fun'
local rspamd_logger = require 'rspamd_logger'
local regexp = require 'rspamd_regexp'
local util = require 'rspamd_util'

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

local function chope(regle, tache)
	local contenus
	local tacheTravail = { t = tache }

	-- Extraction des contenus à analyser.
	
	if regle.type == 'r' then
		contenus = { tache:get_content() }
	elseif regle.type == 'h' then
		contenus = { calculerEnTetes(tacheTravail) }
	-- À FAIRE: les autres cas.
	else
		rspamd_logger.errx(tache, 'unknown type [%s]', regle.type)
	end

	-- Analyse.

	if contenus then
		for _, contenu in ipairs(contenus) do
			if regle.e:match(contenu) then
				return true
			end
		end
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
	local touche = false
	for _, regle in ipairs(this.regles) do
		if chope(regle, tache) then
			points = points + regle.points
			touche = true
		end
	end
	if touche then
		tache:insert_result(this.nom, points)
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
	for l in f:lines() do
		l = l:gsub('^#.*', ''):gsub('[ \t]*[ \t]# .*', ''):gsub('^%s+', ''):gsub('%s+$', '')
		if l:len() then
			local marqueurs, points, exp = l:match('^([a-z]+)[ \t]+(%d+)[ \t]+(.*)$')
			if marqueurs ~= nil and points ~= nil and exp ~= nil then
				local e = regexp.create(exp)
				if not e then
					rspamd_logger.errx(rspamd_config, 'Expression is not a regex: %s', exp)
				else
					local r = { type = marqueurs, points = points, e = e }
					table.insert(regles, r)
				end
			end
		end
	end

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
	
	rspamd_config:register_symbol
	({
		type = 'normal',
		name = nom,
		callback = e:gen_appel(),
	})

	-- Ainsi que le fait qu'il compte.

	rspamd_config:set_metric_symbol
	({
		name = nom,
		score = params['score'],
		description = 'paf set',
		group = N,
	})

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
