package brokers

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"orbguard-lab/internal/domain/models"
)

// BrokerDatabase provides access to the data broker database
type BrokerDatabase struct {
	brokers map[uuid.UUID]*models.DataBroker
	byDomain map[string]*models.DataBroker
	mu      sync.RWMutex
}

// NewBrokerDatabase creates a new broker database with all broker definitions
func NewBrokerDatabase() *BrokerDatabase {
	db := &BrokerDatabase{
		brokers:  make(map[uuid.UUID]*models.DataBroker),
		byDomain: make(map[string]*models.DataBroker),
	}
	db.loadBrokers()
	return db
}

// GetBroker returns a broker by ID
func (db *BrokerDatabase) GetBroker(id uuid.UUID) *models.DataBroker {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.brokers[id]
}

// GetBrokerByDomain returns a broker by domain
func (db *BrokerDatabase) GetBrokerByDomain(domain string) *models.DataBroker {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.byDomain[domain]
}

// GetAllBrokers returns all brokers
func (db *BrokerDatabase) GetAllBrokers() []*models.DataBroker {
	db.mu.RLock()
	defer db.mu.RUnlock()

	brokers := make([]*models.DataBroker, 0, len(db.brokers))
	for _, b := range db.brokers {
		brokers = append(brokers, b)
	}
	return brokers
}

// GetBrokersByCategory returns brokers by category
func (db *BrokerDatabase) GetBrokersByCategory(category models.DataBrokerCategory) []*models.DataBroker {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var brokers []*models.DataBroker
	for _, b := range db.brokers {
		if b.Category == category {
			brokers = append(brokers, b)
		}
	}
	return brokers
}

// GetAutomatable returns brokers that can be automated
func (db *BrokerDatabase) GetAutomatable() []*models.DataBroker {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var brokers []*models.DataBroker
	for _, b := range db.brokers {
		if b.CanAutomate {
			brokers = append(brokers, b)
		}
	}
	return brokers
}

// Count returns total number of brokers
func (db *BrokerDatabase) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.brokers)
}

// Filter returns brokers matching the filter
func (db *BrokerDatabase) Filter(filter models.DataBrokerFilter) []*models.DataBroker {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var result []*models.DataBroker

	for _, b := range db.brokers {
		if matchesFilter(b, filter) {
			result = append(result, b)
		}
	}

	// Apply limit/offset
	if filter.Offset > 0 && filter.Offset < len(result) {
		result = result[filter.Offset:]
	}
	if filter.Limit > 0 && filter.Limit < len(result) {
		result = result[:filter.Limit]
	}

	return result
}

func matchesFilter(b *models.DataBroker, f models.DataBrokerFilter) bool {
	// Category filter
	if len(f.Categories) > 0 {
		found := false
		for _, c := range f.Categories {
			if b.Category == c {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Country filter
	if len(f.Countries) > 0 {
		found := false
		for _, fc := range f.Countries {
			for _, bc := range b.Countries {
				if fc == bc {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}

	// Automation filter
	if f.CanAutomate != nil && *f.CanAutomate != b.CanAutomate {
		return false
	}

	// CCPA filter
	if f.CCPACompliant != nil && *f.CCPACompliant != b.CCPACompliant {
		return false
	}

	// Difficulty filter
	if f.MaxDifficulty != nil && !b.OptOutDifficulty.IsEasierThan(*f.MaxDifficulty) && b.OptOutDifficulty != *f.MaxDifficulty {
		return false
	}

	// Priority filter
	if f.MinPriority != nil && b.Priority < *f.MinPriority {
		return false
	}

	return true
}

func (db *BrokerDatabase) addBroker(b *models.DataBroker) {
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now()
	}
	if b.UpdatedAt.IsZero() {
		b.UpdatedAt = time.Now()
	}
	if b.LastVerified.IsZero() {
		b.LastVerified = time.Now()
	}

	db.brokers[b.ID] = b
	db.byDomain[b.Domain] = b
}

// loadBrokers loads all broker definitions
func (db *BrokerDatabase) loadBrokers() {
	// Load all broker categories
	db.loadPeopleSearchBrokers()
	db.loadMarketingBrokers()
	db.loadB2BLeadBrokers()
	db.loadBackgroundCheckBrokers()
	db.loadPublicRecordsBrokers()
	db.loadFinancialBrokers()
	db.loadLocationBrokers()
	db.loadSocialMediaBrokers()
	db.loadIdentityBrokers()
	db.loadHealthcareBrokers()
	db.loadRecruitmentBrokers()
	db.loadRiskMitigationBrokers()
}

// loadPeopleSearchBrokers loads people search data brokers
func (db *BrokerDatabase) loadPeopleSearchBrokers() {
	brokers := []*models.DataBroker{
		{
			Name:        "Spokeo",
			Domain:      "spokeo.com",
			Category:    models.BrokerPeopleSearch,
			Description: "People search engine aggregating billions of records",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeEmail, models.ExposureTypeRelatives, models.ExposureTypeEmployment,
			},
			Countries:        []string{"US"},
			RecordCount:      "12+ billion records",
			SiteURL:          "https://www.spokeo.com",
			SearchURL:        "https://www.spokeo.com/search",
			OptOutURL:        "https://www.spokeo.com/optout",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			OptOutSteps:      []string{"Find profile URL", "Submit opt-out form", "Verify email"},
			ProcessingDays:   3,
			CanAutomate:      true,
			CCPACompliant:    true,
			GDPRCompliant:    false,
			HonorsRequests:   true,
			Priority:         95,
			Popularity:       100,
		},
		{
			Name:        "BeenVerified",
			Domain:      "beenverified.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Background check and people search service",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeEmail, models.ExposureTypeRelatives, models.ExposureTypeCourtRecord,
			},
			Countries:        []string{"US"},
			RecordCount:      "Billions of records",
			SiteURL:          "https://www.beenverified.com",
			OptOutURL:        "https://www.beenverified.com/app/optout/search",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			OptOutSteps:      []string{"Search for yourself", "Find profile", "Submit opt-out", "Verify email"},
			ProcessingDays:   1,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         95,
			Popularity:       98,
		},
		{
			Name:        "WhitePages",
			Domain:      "whitepages.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Original people search directory service",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeRelatives,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.whitepages.com",
			OptOutURL:        "https://www.whitepages.com/suppression-requests",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			OptOutSteps:      []string{"Find profile", "Request suppression", "Verify phone number"},
			RequiresAccount:  false,
			ProcessingDays:   3,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         90,
			Popularity:       95,
		},
		{
			Name:        "Intelius",
			Domain:      "intelius.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Background check and people search service",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeEmail, models.ExposureTypeRelatives, models.ExposureTypeCourtRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.intelius.com",
			OptOutURL:        "https://www.intelius.com/opt-out",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   7,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         88,
			Popularity:       90,
		},
		{
			Name:        "TruePeopleSearch",
			Domain:      "truepeoplesearch.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Free people search engine",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeRelatives, models.ExposureTypeEmail,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.truepeoplesearch.com",
			OptOutURL:        "https://www.truepeoplesearch.com/removal",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			ProcessingDays:   1,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         92,
			Popularity:       95,
		},
		{
			Name:        "FastPeopleSearch",
			Domain:      "fastpeoplesearch.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Fast free people search",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeRelatives,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.fastpeoplesearch.com",
			OptOutURL:        "https://www.fastpeoplesearch.com/removal",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			ProcessingDays:   1,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         90,
			Popularity:       90,
		},
		{
			Name:        "PeopleFinders",
			Domain:      "peoplefinders.com",
			Category:    models.BrokerPeopleSearch,
			Description: "People search and public records",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeRelatives, models.ExposureTypeCourtRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.peoplefinders.com",
			OptOutURL:        "https://www.peoplefinders.com/opt-out",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   2,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         85,
			Popularity:       85,
		},
		{
			Name:        "Radaris",
			Domain:      "radaris.com",
			Category:    models.BrokerPeopleSearch,
			Description: "People search engine and background checks",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeEmail, models.ExposureTypeRelatives, models.ExposureTypePropertyRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://radaris.com",
			OptOutURL:        "https://radaris.com/control/privacy",
			OptOutMethod:     models.OptOutMethodAccountReq,
			OptOutDifficulty: models.OptOutDifficultyHard,
			RequiresAccount:  true,
			ProcessingDays:   7,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         82,
			Popularity:       80,
		},
		{
			Name:        "USSearch",
			Domain:      "ussearch.com",
			Category:    models.BrokerPeopleSearch,
			Description: "People search and background checks",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeRelatives,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.ussearch.com",
			OptOutURL:        "https://www.ussearch.com/opt-out/submit/",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   5,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         78,
			Popularity:       75,
		},
		{
			Name:        "ThatsThem",
			Domain:      "thatsthem.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Free people search",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeEmail, models.ExposureTypeIPAddress,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://thatsthem.com",
			OptOutURL:        "https://thatsthem.com/optout",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			ProcessingDays:   1,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         80,
			Popularity:       78,
		},
		{
			Name:        "Instant Checkmate",
			Domain:      "instantcheckmate.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Background check service",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeCourtRecord, models.ExposureTypeRelatives,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.instantcheckmate.com",
			OptOutURL:        "https://www.instantcheckmate.com/opt-out/",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   2,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         85,
			Popularity:       82,
		},
		{
			Name:        "TruthFinder",
			Domain:      "truthfinder.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Background check and people search",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeCourtRecord, models.ExposureTypeRelatives, models.ExposureTypePropertyRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.truthfinder.com",
			OptOutURL:        "https://www.truthfinder.com/opt-out/",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   3,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         86,
			Popularity:       84,
		},
		{
			Name:        "Pipl",
			Domain:      "pipl.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Identity resolution platform",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypePhone,
				models.ExposureTypeSocialProfile, models.ExposureTypePhoto,
			},
			Countries:        []string{"US", "UK", "EU"},
			SiteURL:          "https://pipl.com",
			OptOutURL:        "https://pipl.com/personal-information-removal-request",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   14,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         88,
			Popularity:       75,
		},
		{
			Name:        "Nuwber",
			Domain:      "nuwber.com",
			Category:    models.BrokerPeopleSearch,
			Description: "People search engine",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeEmail, models.ExposureTypeRelatives,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://nuwber.com",
			OptOutURL:        "https://nuwber.com/removal/link",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			ProcessingDays:   2,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         80,
			Popularity:       76,
		},
		{
			Name:        "Clustrmaps",
			Domain:      "clustrmaps.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Address and people search",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://clustrmaps.com",
			OptOutURL:        "https://clustrmaps.com/bl/opt-out",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			ProcessingDays:   3,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         65,
			Popularity:       60,
		},
		{
			Name:        "CyberBackgroundChecks",
			Domain:      "cyberbackgroundchecks.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Background check service",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeCourtRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.cyberbackgroundchecks.com",
			OptOutURL:        "https://www.cyberbackgroundchecks.com/removal",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   5,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         72,
			Popularity:       68,
		},
		{
			Name:        "PublicRecordsNow",
			Domain:      "publicrecordsnow.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Public records search",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypeCourtRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.publicrecordsnow.com",
			OptOutURL:        "https://www.publicrecordsnow.com/optout",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   5,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         68,
			Popularity:       62,
		},
		{
			Name:        "SearchPeopleFree",
			Domain:      "searchpeoplefree.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Free people search",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.searchpeoplefree.com",
			OptOutURL:        "https://www.searchpeoplefree.com/optout",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			ProcessingDays:   3,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         70,
			Popularity:       65,
		},
		{
			Name:        "PeekYou",
			Domain:      "peekyou.com",
			Category:    models.BrokerPeopleSearch,
			Description: "People search aggregating social and web data",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeSocialProfile, models.ExposureTypeLocation,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.peekyou.com",
			OptOutURL:        "https://www.peekyou.com/about/contact/optout",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   7,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         75,
			Popularity:       72,
		},
		{
			Name:        "Addresses.com",
			Domain:      "addresses.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Address lookup service",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.addresses.com",
			OptOutURL:        "https://www.addresses.com/optout.php",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			ProcessingDays:   3,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         65,
			Popularity:       60,
		},
		{
			Name:        "411.com",
			Domain:      "411.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Phone and people directory",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.411.com",
			OptOutURL:        "https://www.411.com/privacy",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   5,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         68,
			Popularity:       65,
		},
		{
			Name:        "AnyWho",
			Domain:      "anywho.com",
			Category:    models.BrokerPeopleSearch,
			Description: "People and phone directory",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.anywho.com",
			OptOutURL:        "https://www.intelius.com/opt-out",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   7,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         62,
			Popularity:       58,
		},
		{
			Name:        "Neighbor.Report",
			Domain:      "neighbor.report",
			Category:    models.BrokerPeopleSearch,
			Description: "Neighborhood and people information",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePropertyRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://neighbor.report",
			OptOutURL:        "https://neighbor.report/remove",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   5,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         60,
			Popularity:       55,
		},
		{
			Name:        "AdvancedBackgroundChecks",
			Domain:      "advancedbackgroundchecks.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Background check service",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeCourtRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.advancedbackgroundchecks.com",
			OptOutURL:        "https://www.advancedbackgroundchecks.com/removal",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   5,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         70,
			Popularity:       65,
		},
		{
			Name:        "CheckPeople",
			Domain:      "checkpeople.com",
			Category:    models.BrokerPeopleSearch,
			Description: "People search and background checks",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://checkpeople.com",
			OptOutURL:        "https://checkpeople.com/do-not-sell-my-info",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			ProcessingDays:   3,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         72,
			Popularity:       68,
		},
		{
			Name:        "IDTrue",
			Domain:      "idtrue.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Identity verification and people search",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeEmail,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.idtrue.com",
			OptOutURL:        "https://www.idtrue.com/optout/",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   5,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         68,
			Popularity:       62,
		},
		{
			Name:        "PeopleSmart",
			Domain:      "peoplesmart.com",
			Category:    models.BrokerPeopleSearch,
			Description: "People search service",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeEmail,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.peoplesmart.com",
			OptOutURL:        "https://www.peoplesmart.com/optout-go",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   5,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         70,
			Popularity:       66,
		},
		{
			Name:        "Spytox",
			Domain:      "spytox.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Reverse phone and people lookup",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypePhone, models.ExposureTypeAddress,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.spytox.com",
			OptOutURL:        "https://www.spytox.com/optout",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			ProcessingDays:   3,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         65,
			Popularity:       60,
		},
		{
			Name:        "Verecor",
			Domain:      "verecor.com",
			Category:    models.BrokerPeopleSearch,
			Description: "People search and records",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://verecor.com",
			OptOutURL:        "https://verecor.com/ng/control/privacy",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   5,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         62,
			Popularity:       55,
		},
		{
			Name:        "VoterRecords",
			Domain:      "voterrecords.com",
			Category:    models.BrokerPeopleSearch,
			Description: "Voter registration records",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://voterrecords.com",
			OptOutURL:        "https://voterrecords.com/optout",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   7,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         58,
			Popularity:       50,
		},
	}

	for _, b := range brokers {
		db.addBroker(b)
	}
}

// loadMarketingBrokers loads marketing data brokers
func (db *BrokerDatabase) loadMarketingBrokers() {
	brokers := []*models.DataBroker{
		{
			Name:        "Acxiom",
			Domain:      "acxiom.com",
			Category:    models.BrokerMarketing,
			Description: "One of the largest consumer data brokers",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePhone,
				models.ExposureTypeEmail, models.ExposureTypeDateOfBirth, models.ExposureTypeEmployment,
			},
			Countries:        []string{"US", "UK", "EU"},
			RecordCount:      "2.5+ billion records",
			SiteURL:          "https://www.acxiom.com",
			OptOutURL:        "https://isapps.acxiom.com/optout/optout.aspx",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         95,
			Popularity:       85,
		},
		{
			Name:        "Oracle Data Cloud (BlueKai)",
			Domain:      "oracle.com",
			Category:    models.BrokerMarketing,
			Description: "Marketing data cloud platform",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypeLocation,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://www.oracle.com/data-cloud/",
			OptOutURL:        "https://www.oracle.com/legal/privacy/marketing-cloud-data-cloud-privacy-policy.html",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         90,
			Popularity:       80,
		},
		{
			Name:        "Epsilon",
			Domain:      "epsilon.com",
			Category:    models.BrokerMarketing,
			Description: "Marketing data and services company",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypeEmail,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.epsilon.com",
			OptOutURL:        "https://www.epsilon.com/privacy-policy/#opt-out",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         88,
			Popularity:       75,
		},
		{
			Name:        "Experian Marketing Services",
			Domain:      "experian.com",
			Category:    models.BrokerMarketing,
			Description: "Marketing data services from credit bureau",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypeEmail,
			},
			Countries:        []string{"US", "UK"},
			SiteURL:          "https://www.experian.com/marketing-services",
			OptOutURL:        "https://www.experian.com/privacy/opting_out_preapproved_offers",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyHard,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         92,
			Popularity:       88,
		},
		{
			Name:        "LiveRamp",
			Domain:      "liveramp.com",
			Category:    models.BrokerMarketing,
			Description: "Identity resolution and data connectivity",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypePhone,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://liveramp.com",
			OptOutURL:        "https://optout.liveramp.com/opt_out",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			ProcessingDays:   14,
			CanAutomate:      true,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         85,
			Popularity:       78,
		},
		{
			Name:        "Nielsen",
			Domain:      "nielsen.com",
			Category:    models.BrokerMarketing,
			Description: "Market research and consumer data",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypeLocation,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://www.nielsen.com",
			OptOutURL:        "https://www.nielsen.com/us/en/legal/privacy-statement/digital-measurement/",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         82,
			Popularity:       75,
		},
		{
			Name:        "CoreLogic",
			Domain:      "corelogic.com",
			Category:    models.BrokerMarketing,
			Description: "Property and consumer data",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePropertyRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.corelogic.com",
			OptOutURL:        "https://www.corelogic.com/privacy.aspx",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyHard,
			ProcessingDays:   45,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         80,
			Popularity:       70,
		},
		{
			Name:        "Tapad",
			Domain:      "tapad.com",
			Category:    models.BrokerMarketing,
			Description: "Cross-device identity platform",
			DataTypes: []models.ExposureType{
				models.ExposureTypeEmail, models.ExposureTypeIPAddress,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://www.tapad.com",
			OptOutURL:        "https://www.tapad.com/privacy-policy",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         72,
			Popularity:       65,
		},
		{
			Name:        "TransUnion Marketing Solutions",
			Domain:      "transunion.com",
			Category:    models.BrokerMarketing,
			Description: "Marketing services from credit bureau",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypeEmail,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.transunion.com",
			OptOutURL:        "https://www.transunion.com/consumer-privacy",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyHard,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         90,
			Popularity:       85,
		},
		{
			Name:        "Lotame",
			Domain:      "lotame.com",
			Category:    models.BrokerMarketing,
			Description: "Data management platform",
			DataTypes: []models.ExposureType{
				models.ExposureTypeEmail, models.ExposureTypeLocation,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://www.lotame.com",
			OptOutURL:        "https://www.lotame.com/about-lotame/privacy/opt-out/",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			ProcessingDays:   14,
			CanAutomate:      true,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         70,
			Popularity:       62,
		},
	}

	for _, b := range brokers {
		db.addBroker(b)
	}
}

// loadB2BLeadBrokers loads B2B lead generation brokers
func (db *BrokerDatabase) loadB2BLeadBrokers() {
	brokers := []*models.DataBroker{
		{
			Name:        "ZoomInfo",
			Domain:      "zoominfo.com",
			Category:    models.BrokerB2BLead,
			Description: "B2B contact and company database",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypePhone,
				models.ExposureTypeEmployment,
			},
			Countries:        []string{"US", "EU"},
			RecordCount:      "200+ million contacts",
			SiteURL:          "https://www.zoominfo.com",
			OptOutURL:        "https://www.zoominfo.com/about-zoominfo/privacy-manage-profile",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         90,
			Popularity:       88,
		},
		{
			Name:        "Apollo.io",
			Domain:      "apollo.io",
			Category:    models.BrokerB2BLead,
			Description: "Sales intelligence platform",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypePhone,
				models.ExposureTypeEmployment,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://www.apollo.io",
			OptOutURL:        "https://www.apollo.io/privacy-policy/remove-my-information",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   14,
			CanAutomate:      true,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         85,
			Popularity:       82,
		},
		{
			Name:        "Clearbit",
			Domain:      "clearbit.com",
			Category:    models.BrokerB2BLead,
			Description: "B2B data enrichment",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypeEmployment,
				models.ExposureTypeSocialProfile,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://clearbit.com",
			OptOutURL:        "https://clearbit.com/privacy",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         82,
			Popularity:       78,
		},
		{
			Name:        "Lusha",
			Domain:      "lusha.com",
			Category:    models.BrokerB2BLead,
			Description: "B2B contact information",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypePhone,
				models.ExposureTypeEmployment,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://www.lusha.com",
			OptOutURL:        "https://www.lusha.com/opt-out/",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			ProcessingDays:   7,
			CanAutomate:      true,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         80,
			Popularity:       76,
		},
		{
			Name:        "Lead411",
			Domain:      "lead411.com",
			Category:    models.BrokerB2BLead,
			Description: "Sales intelligence and leads",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypePhone,
				models.ExposureTypeEmployment,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.lead411.com",
			OptOutURL:        "https://www.lead411.com/privacy",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   14,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         72,
			Popularity:       68,
		},
		{
			Name:        "Hunter.io",
			Domain:      "hunter.io",
			Category:    models.BrokerB2BLead,
			Description: "Email finder tool",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypeEmployment,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://hunter.io",
			OptOutURL:        "https://hunter.io/claim",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			ProcessingDays:   3,
			CanAutomate:      true,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         75,
			Popularity:       72,
		},
		{
			Name:        "RocketReach",
			Domain:      "rocketreach.co",
			Category:    models.BrokerB2BLead,
			Description: "Professional contact search",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypePhone,
				models.ExposureTypeEmployment, models.ExposureTypeSocialProfile,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://rocketreach.co",
			OptOutURL:        "https://rocketreach.co/optout",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			ProcessingDays:   7,
			CanAutomate:      true,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         78,
			Popularity:       74,
		},
		{
			Name:        "SalesIntel",
			Domain:      "salesintel.io",
			Category:    models.BrokerB2BLead,
			Description: "B2B sales intelligence",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypePhone,
				models.ExposureTypeEmployment,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://salesintel.io",
			OptOutURL:        "https://salesintel.io/privacy-policy/",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   14,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         70,
			Popularity:       65,
		},
		{
			Name:        "Cognism",
			Domain:      "cognism.com",
			Category:    models.BrokerB2BLead,
			Description: "B2B sales intelligence platform",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypePhone,
				models.ExposureTypeEmployment,
			},
			Countries:        []string{"US", "UK", "EU"},
			SiteURL:          "https://www.cognism.com",
			OptOutURL:        "https://www.cognism.com/do-not-sell-my-info",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   14,
			CanAutomate:      true,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         76,
			Popularity:       70,
		},
		{
			Name:        "UpLead",
			Domain:      "uplead.com",
			Category:    models.BrokerB2BLead,
			Description: "B2B prospecting platform",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypePhone,
				models.ExposureTypeEmployment,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.uplead.com",
			OptOutURL:        "https://www.uplead.com/privacy-policy",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   14,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         68,
			Popularity:       62,
		},
	}

	for _, b := range brokers {
		db.addBroker(b)
	}
}

// loadBackgroundCheckBrokers loads background check brokers
func (db *BrokerDatabase) loadBackgroundCheckBrokers() {
	brokers := []*models.DataBroker{
		{
			Name:        "Checkr",
			Domain:      "checkr.com",
			Category:    models.BrokerBackground,
			Description: "Employment background checks",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeSSN, models.ExposureTypeCourtRecord,
				models.ExposureTypeEmployment, models.ExposureTypeEducation,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://checkr.com",
			OptOutURL:        "https://checkr.com/privacy-policy",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyHard,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         85,
			Popularity:       80,
		},
		{
			Name:        "GoodHire",
			Domain:      "goodhire.com",
			Category:    models.BrokerBackground,
			Description: "Employment screening",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeSSN, models.ExposureTypeCourtRecord,
				models.ExposureTypeEmployment,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.goodhire.com",
			OptOutURL:        "https://www.goodhire.com/privacy-policy",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyHard,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         78,
			Popularity:       72,
		},
		{
			Name:        "Sterling",
			Domain:      "sterlingcheck.com",
			Category:    models.BrokerBackground,
			Description: "Background and identity services",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeSSN, models.ExposureTypeCourtRecord,
				models.ExposureTypeEmployment, models.ExposureTypeEducation,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.sterlingcheck.com",
			OptOutURL:        "https://www.sterlingcheck.com/privacy-notice/",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyHard,
			ProcessingDays:   45,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         82,
			Popularity:       75,
		},
		{
			Name:        "HireRight",
			Domain:      "hireright.com",
			Category:    models.BrokerBackground,
			Description: "Employment verification and screening",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeSSN, models.ExposureTypeCourtRecord,
				models.ExposureTypeEmployment, models.ExposureTypeDriverLicense,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.hireright.com",
			OptOutURL:        "https://www.hireright.com/privacy-policy",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyHard,
			ProcessingDays:   45,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         80,
			Popularity:       74,
		},
		{
			Name:        "First Advantage",
			Domain:      "fadv.com",
			Category:    models.BrokerBackground,
			Description: "Background screening services",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeSSN, models.ExposureTypeCourtRecord,
				models.ExposureTypeEmployment, models.ExposureTypeEducation,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://fadv.com",
			OptOutURL:        "https://fadv.com/privacy-policy/",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyHard,
			ProcessingDays:   45,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         78,
			Popularity:       72,
		},
	}

	for _, b := range brokers {
		db.addBroker(b)
	}
}

// loadPublicRecordsBrokers loads public records brokers
func (db *BrokerDatabase) loadPublicRecordsBrokers() {
	brokers := []*models.DataBroker{
		{
			Name:        "BeenVerified Property",
			Domain:      "beenverified.com/property",
			Category:    models.BrokerPublicRecords,
			Description: "Property records search",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePropertyRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.beenverified.com/property/",
			OptOutURL:        "https://www.beenverified.com/app/optout/search",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   1,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         75,
			Popularity:       70,
		},
		{
			Name:        "PropertyShark",
			Domain:      "propertyshark.com",
			Category:    models.BrokerPublicRecords,
			Description: "Real estate and property data",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePropertyRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.propertyshark.com",
			OptOutURL:        "https://www.propertyshark.com/info/privacy-policy",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   14,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         65,
			Popularity:       60,
		},
		{
			Name:        "Zillow",
			Domain:      "zillow.com",
			Category:    models.BrokerPublicRecords,
			Description: "Real estate marketplace",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePropertyRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.zillow.com",
			OptOutURL:        "https://www.zillow.com/z/corp/privacy/",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyHard,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         72,
			Popularity:       85,
		},
		{
			Name:        "Realtor.com",
			Domain:      "realtor.com",
			Category:    models.BrokerPublicRecords,
			Description: "Real estate listings and data",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePropertyRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.realtor.com",
			OptOutURL:        "https://www.realtor.com/privacy/",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         70,
			Popularity:       80,
		},
		{
			Name:        "Redfin",
			Domain:      "redfin.com",
			Category:    models.BrokerPublicRecords,
			Description: "Real estate brokerage and data",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypePropertyRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.redfin.com",
			OptOutURL:        "https://www.redfin.com/about/privacy-policy",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         68,
			Popularity:       78,
		},
		{
			Name:        "CourtListener (RECAP)",
			Domain:      "courtlistener.com",
			Category:    models.BrokerPublicRecords,
			Description: "Federal court records database",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeCourtRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.courtlistener.com",
			OptOutURL:        "https://www.courtlistener.com/help/removal/",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyHard,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         60,
			Popularity:       55,
		},
	}

	for _, b := range brokers {
		db.addBroker(b)
	}
}

// loadFinancialBrokers loads financial data brokers
func (db *BrokerDatabase) loadFinancialBrokers() {
	brokers := []*models.DataBroker{
		{
			Name:        "Equifax",
			Domain:      "equifax.com",
			Category:    models.BrokerFinancial,
			Description: "Major credit bureau",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeSSN, models.ExposureTypeAddress,
				models.ExposureTypeCreditCard, models.ExposureTypeBankAccount,
			},
			Countries:        []string{"US", "UK", "CA"},
			RecordCount:      "800+ million records",
			SiteURL:          "https://www.equifax.com",
			OptOutURL:        "https://www.equifax.com/personal/credit-report-services/credit-freeze/",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyHard,
			RequiresID:       true,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         100,
			Popularity:       100,
		},
		{
			Name:        "Experian",
			Domain:      "experian.com",
			Category:    models.BrokerFinancial,
			Description: "Major credit bureau",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeSSN, models.ExposureTypeAddress,
				models.ExposureTypeCreditCard, models.ExposureTypeBankAccount,
			},
			Countries:        []string{"US", "UK"},
			RecordCount:      "1+ billion records",
			SiteURL:          "https://www.experian.com",
			OptOutURL:        "https://www.experian.com/freeze/center.html",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyHard,
			RequiresID:       true,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         100,
			Popularity:       100,
		},
		{
			Name:        "TransUnion",
			Domain:      "transunion.com",
			Category:    models.BrokerFinancial,
			Description: "Major credit bureau",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeSSN, models.ExposureTypeAddress,
				models.ExposureTypeCreditCard, models.ExposureTypeBankAccount,
			},
			Countries:        []string{"US", "CA"},
			RecordCount:      "1+ billion records",
			SiteURL:          "https://www.transunion.com",
			OptOutURL:        "https://www.transunion.com/credit-freeze",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyHard,
			RequiresID:       true,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         100,
			Popularity:       100,
		},
		{
			Name:        "ChexSystems",
			Domain:      "chexsystems.com",
			Category:    models.BrokerFinancial,
			Description: "Banking history reports",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeSSN, models.ExposureTypeBankAccount,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.chexsystems.com",
			OptOutURL:        "https://www.chexsystems.com/security-freeze/",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyHard,
			RequiresID:       true,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         85,
			Popularity:       70,
		},
		{
			Name:        "Innovis",
			Domain:      "innovis.com",
			Category:    models.BrokerFinancial,
			Description: "Fourth credit bureau",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeSSN, models.ExposureTypeAddress,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.innovis.com",
			OptOutURL:        "https://www.innovis.com/securityFreeze/index",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyHard,
			RequiresID:       true,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         80,
			Popularity:       60,
		},
	}

	for _, b := range brokers {
		db.addBroker(b)
	}
}

// loadLocationBrokers loads location data brokers
func (db *BrokerDatabase) loadLocationBrokers() {
	brokers := []*models.DataBroker{
		{
			Name:        "Foursquare",
			Domain:      "foursquare.com",
			Category:    models.BrokerLocation,
			Description: "Location data platform",
			DataTypes: []models.ExposureType{
				models.ExposureTypeLocation, models.ExposureTypeUsername,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://foursquare.com",
			OptOutURL:        "https://foursquare.com/privacy",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         72,
			Popularity:       68,
		},
		{
			Name:        "SafeGraph",
			Domain:      "safegraph.com",
			Category:    models.BrokerLocation,
			Description: "Location intelligence data",
			DataTypes: []models.ExposureType{
				models.ExposureTypeLocation,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.safegraph.com",
			OptOutURL:        "https://www.safegraph.com/privacy-policy",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         70,
			Popularity:       60,
		},
		{
			Name:        "Placer.ai",
			Domain:      "placer.ai",
			Category:    models.BrokerLocation,
			Description: "Foot traffic analytics",
			DataTypes: []models.ExposureType{
				models.ExposureTypeLocation,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.placer.ai",
			OptOutURL:        "https://www.placer.ai/privacy-policy",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         65,
			Popularity:       55,
		},
		{
			Name:        "X-Mode Social",
			Domain:      "xmode.io",
			Category:    models.BrokerLocation,
			Description: "Location data aggregator",
			DataTypes: []models.ExposureType{
				models.ExposureTypeLocation, models.ExposureTypeIPAddress,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://xmode.io",
			OptOutURL:        "https://xmode.io/optout/",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyEasy,
			ProcessingDays:   14,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         75,
			Popularity:       62,
		},
	}

	for _, b := range brokers {
		db.addBroker(b)
	}
}

// loadSocialMediaBrokers loads social media data aggregators
func (db *BrokerDatabase) loadSocialMediaBrokers() {
	brokers := []*models.DataBroker{
		{
			Name:        "Pipl",
			Domain:      "pipl.com",
			Category:    models.BrokerSocialMedia,
			Description: "Social profile aggregator",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeSocialProfile, models.ExposureTypeEmail,
				models.ExposureTypePhoto,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://pipl.com",
			OptOutURL:        "https://pipl.com/personal-information-removal-request",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   14,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         85,
			Popularity:       78,
		},
		{
			Name:        "Social Catfish",
			Domain:      "socialcatfish.com",
			Category:    models.BrokerSocialMedia,
			Description: "Social media search and verification",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeSocialProfile, models.ExposureTypePhoto,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://socialcatfish.com",
			OptOutURL:        "https://socialcatfish.com/opt-out/",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   7,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         70,
			Popularity:       65,
		},
		{
			Name:        "Clearview AI",
			Domain:      "clearview.ai",
			Category:    models.BrokerSocialMedia,
			Description: "Facial recognition from social media",
			DataTypes: []models.ExposureType{
				models.ExposureTypePhoto, models.ExposureTypeName, models.ExposureTypeSocialProfile,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.clearview.ai",
			OptOutURL:        "https://clearview.ai/privacy/requests",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyHard,
			RequiresID:       true,
			ProcessingDays:   45,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         95,
			Popularity:       60,
		},
		{
			Name:        "PimEyes",
			Domain:      "pimeyes.com",
			Category:    models.BrokerSocialMedia,
			Description: "Facial recognition search engine",
			DataTypes: []models.ExposureType{
				models.ExposureTypePhoto, models.ExposureTypeSocialProfile,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://pimeyes.com",
			OptOutURL:        "https://pimeyes.com/en/opt-out-request",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   14,
			CanAutomate:      true,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         88,
			Popularity:       55,
		},
	}

	for _, b := range brokers {
		db.addBroker(b)
	}
}

// loadIdentityBrokers loads identity verification brokers
func (db *BrokerDatabase) loadIdentityBrokers() {
	brokers := []*models.DataBroker{
		{
			Name:        "LexisNexis",
			Domain:      "lexisnexis.com",
			Category:    models.BrokerIdentity,
			Description: "Risk solutions and identity verification",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeSSN, models.ExposureTypeAddress,
				models.ExposureTypeDateOfBirth, models.ExposureTypeDriverLicense,
			},
			Countries:        []string{"US"},
			RecordCount:      "Billions of records",
			SiteURL:          "https://risk.lexisnexis.com",
			OptOutURL:        "https://optout.lexisnexis.com/",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyHard,
			RequiresID:       true,
			ProcessingDays:   45,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         95,
			Popularity:       85,
		},
		{
			Name:        "Thomson Reuters CLEAR",
			Domain:      "clear.thomsonreuters.com",
			Category:    models.BrokerIdentity,
			Description: "Identity and investigation platform",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeSSN, models.ExposureTypeAddress,
				models.ExposureTypeCourtRecord, models.ExposureTypePropertyRecord,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://legal.thomsonreuters.com/en/products/clear-investigation-software",
			OptOutURL:        "https://www.thomsonreuters.com/en/privacy-policy.html",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyVeryHard,
			RequiresID:       true,
			ProcessingDays:   60,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         90,
			Popularity:       70,
		},
		{
			Name:        "RELX (Reed Elsevier)",
			Domain:      "relx.com",
			Category:    models.BrokerIdentity,
			Description: "Risk and business analytics",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeAddress, models.ExposureTypeEmployment,
			},
			Countries:        []string{"US", "UK", "EU"},
			SiteURL:          "https://www.relx.com",
			OptOutURL:        "https://www.relx.com/our-business/our-stories/privacy",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyHard,
			ProcessingDays:   45,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         78,
			Popularity:       60,
		},
	}

	for _, b := range brokers {
		db.addBroker(b)
	}
}

// loadHealthcareBrokers loads healthcare data brokers
func (db *BrokerDatabase) loadHealthcareBrokers() {
	brokers := []*models.DataBroker{
		{
			Name:        "IMS Health (IQVIA)",
			Domain:      "iqvia.com",
			Category:    models.BrokerHealthcare,
			Description: "Healthcare data and analytics",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeDateOfBirth,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.iqvia.com",
			OptOutURL:        "https://www.iqvia.com/about-us/privacy",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyVeryHard,
			ProcessingDays:   60,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         70,
			Popularity:       50,
		},
		{
			Name:        "MIB Group",
			Domain:      "mib.com",
			Category:    models.BrokerHealthcare,
			Description: "Insurance information exchange",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeDateOfBirth, models.ExposureTypeSSN,
			},
			Countries:        []string{"US", "CA"},
			SiteURL:          "https://www.mib.com",
			OptOutURL:        "https://www.mib.com/request_your_record.html",
			OptOutMethod:     models.OptOutMethodMail,
			OptOutDifficulty: models.OptOutDifficultyVeryHard,
			RequiresID:       true,
			ProcessingDays:   45,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         75,
			Popularity:       45,
		},
	}

	for _, b := range brokers {
		db.addBroker(b)
	}
}

// loadRecruitmentBrokers loads recruitment data brokers
func (db *BrokerDatabase) loadRecruitmentBrokers() {
	brokers := []*models.DataBroker{
		{
			Name:        "LinkedIn",
			Domain:      "linkedin.com",
			Category:    models.BrokerRecruitment,
			Description: "Professional networking platform",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypeEmployment,
				models.ExposureTypeEducation, models.ExposureTypeSocialProfile, models.ExposureTypePhoto,
			},
			Countries:        []string{"US", "EU"},
			RecordCount:      "900+ million members",
			SiteURL:          "https://www.linkedin.com",
			OptOutURL:        "https://www.linkedin.com/psettings/guest-controls",
			OptOutMethod:     models.OptOutMethodAccountReq,
			OptOutDifficulty: models.OptOutDifficultyHard,
			RequiresAccount:  true,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         90,
			Popularity:       100,
		},
		{
			Name:        "Indeed",
			Domain:      "indeed.com",
			Category:    models.BrokerRecruitment,
			Description: "Job search platform",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypeEmployment,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://www.indeed.com",
			OptOutURL:        "https://www.indeed.com/legal/ccpa-dns",
			OptOutMethod:     models.OptOutMethodAccountReq,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			RequiresAccount:  true,
			ProcessingDays:   14,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         78,
			Popularity:       90,
		},
		{
			Name:        "Glassdoor",
			Domain:      "glassdoor.com",
			Category:    models.BrokerRecruitment,
			Description: "Job reviews and search platform",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypeEmployment,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://www.glassdoor.com",
			OptOutURL:        "https://help.glassdoor.com/s/article/Delete-My-Account",
			OptOutMethod:     models.OptOutMethodAccountReq,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			RequiresAccount:  true,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         72,
			Popularity:       85,
		},
		{
			Name:        "Monster",
			Domain:      "monster.com",
			Category:    models.BrokerRecruitment,
			Description: "Job search platform",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypeEmployment,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.monster.com",
			OptOutURL:        "https://www.monster.com/privacy/ccpa-opt-out",
			OptOutMethod:     models.OptOutMethodAccountReq,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			RequiresAccount:  true,
			ProcessingDays:   14,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         65,
			Popularity:       70,
		},
	}

	for _, b := range brokers {
		db.addBroker(b)
	}
}

// loadRiskMitigationBrokers loads risk mitigation brokers
func (db *BrokerDatabase) loadRiskMitigationBrokers() {
	brokers := []*models.DataBroker{
		{
			Name:        "SEON",
			Domain:      "seon.io",
			Category:    models.BrokerRiskMitigation,
			Description: "Fraud prevention platform",
			DataTypes: []models.ExposureType{
				models.ExposureTypeEmail, models.ExposureTypePhone, models.ExposureTypeSocialProfile,
			},
			Countries:        []string{"US", "EU"},
			SiteURL:          "https://seon.io",
			OptOutURL:        "https://seon.io/privacy-policy/",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			GDPRCompliant:    true,
			HonorsRequests:   true,
			Priority:         68,
			Popularity:       55,
		},
		{
			Name:        "Ekata",
			Domain:      "ekata.com",
			Category:    models.BrokerRiskMitigation,
			Description: "Identity verification API",
			DataTypes: []models.ExposureType{
				models.ExposureTypeName, models.ExposureTypeEmail, models.ExposureTypePhone,
				models.ExposureTypeAddress,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://ekata.com",
			OptOutURL:        "https://ekata.com/consumer-opt-out/",
			OptOutMethod:     models.OptOutMethodWebForm,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   30,
			CanAutomate:      true,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         70,
			Popularity:       58,
		},
		{
			Name:        "TeleSign",
			Domain:      "telesign.com",
			Category:    models.BrokerRiskMitigation,
			Description: "Phone intelligence and verification",
			DataTypes: []models.ExposureType{
				models.ExposureTypePhone, models.ExposureTypeName,
			},
			Countries:        []string{"US"},
			SiteURL:          "https://www.telesign.com",
			OptOutURL:        "https://www.telesign.com/privacy-policy",
			OptOutMethod:     models.OptOutMethodEmail,
			OptOutDifficulty: models.OptOutDifficultyMedium,
			ProcessingDays:   30,
			CanAutomate:      false,
			CCPACompliant:    true,
			HonorsRequests:   true,
			Priority:         65,
			Popularity:       52,
		},
	}

	for _, b := range brokers {
		db.addBroker(b)
	}
}
